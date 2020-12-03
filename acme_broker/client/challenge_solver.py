import abc
import asyncio
import contextlib
import functools
import logging

import acme.messages
import dns.asyncresolver
import josepy
import typing
from infoblox_client import connector, objects

from acme_broker.models import ChallengeType
from acme_broker.util import ConfigurableMixin

logger = logging.getLogger(__name__)


class ChallengeSolver(ConfigurableMixin, abc.ABC):
    """An abstract base class for challenge solver clients.

    All challenge solver implementations must implement the method :func:`complete_challenge`
    that provisions the resources that are needed to complete the given challenge and delays execution until
    the server may check for completion.
    Implementations must also set the :attr:`config_name` attribute, so that the CLI script knows which
    configuration option corresponds to which challenge solver class.
    """

    config_name: str
    """The string that maps to the solver implementation inside configuration files."""

    SUPPORTED_CHALLENGES: typing.Iterable[ChallengeType]
    """The types of challenges that the challenge solver implementation supports."""

    subclasses = []

    async def connect(self):
        """Handles connecting the solver implementation to its remote API.

        Must not be overridden if no initial connection is required.
        """
        pass

    @abc.abstractmethod
    async def complete_challenge(
        self,
        key: josepy.jwk.JWKRSA,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
        """Complete the given challenge.

        This method should complete the given challenge and then delay
        returning until the server is allowed to check for completion.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to be completed.
        :raises: :class:`asyncio.TimeoutError` If the challenge completion attempt timed out.
        """
        pass


class DummySolver(ChallengeSolver):
    """Dummy challenge solver that does not actually complete any challenges."""

    config_name = "dummy"

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.DNS_01, ChallengeType.HTTP_01])
    """The types of challenges that the solver supports."""

    async def complete_challenge(
        self,
        key: josepy.jwk.JWKRSA,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
        """Does not complete the given challenge.

        Instead, this method only logs the mock completion attempt and pauses
        execution for one second.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to be completed.
        """
        logger.debug(
            f"(not) solving challenge {challenge.uri}, type {challenge.chall.typ}, identifier {identifier}"
        )
        # await asyncio.sleep(1)


class InfobloxClient(ChallengeSolver):
    """InfoBlox DNS-01 challenge solver.

    This challenge solver connects to an InfoBlox API to provision
    DNS TXT records in order to complete the ACME DNS-01 challenge type.
    """

    config_name = "infoblox"

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.DNS_01])
    """The types of challenges that the solver supports."""

    POLLING_DELAY = 1.0
    """Time in seconds between consecutive DNS requests."""

    POLLING_TIMEOUT = 60.0
    """Time in seconds after which placing the TXT record is considered failed."""

    DEFAULT_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]
    """The DNS servers to use if none are specified during initialization."""

    DEFAULT_VIEWS = ["Extern"]
    """The views to use if none are specified during initialization."""

    def __init__(self, *, host, username, password, dns_servers=None, views=None):
        self._creds = {"host": host, "username": username, "password": password}
        self._loop = asyncio.get_event_loop()

        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.nameservers = dns_servers or self.DEFAULT_DNS_SERVERS

        self._views = views or self.DEFAULT_VIEWS

    async def connect(self):
        """Connect to the InfoBlox API.

        This method must be called before attempting to complete challenges.
        """
        self._conn = await self._loop.run_in_executor(
            None, connector.Connector, self._creds
        )

    async def set_txt_record(self, name: str, text: str, views=None, ttl: int = 60):
        """Sets a DNS TXT record.

        :param name: The name of the TXT record.
        :param text: The text of the TXT record.
        :param views: List of views to set the TXT record in. Defaults to *Intern* and *Extern*.
        :param ttl: Time to live of the TXT record in seconds.
        """
        views = views or self._views

        logger.debug("Setting TXT record %s = %s, TTL %d", name, text, ttl)

        # Infoblox-client exceptions are propagated.
        await asyncio.gather(
            *[
                self._loop.run_in_executor(
                    None,
                    functools.partial(
                        objects.TXTRecord.create,
                        self._conn,
                        name=name,
                        text=text,
                        view=view,
                        ttl=ttl,
                        update_if_exists=True,
                    ),
                )
                for view in views
            ]
        )

    async def query_txt_record(self, name: str) -> typing.List[str]:
        """Queries a DNS TXT record.

        :param name: Name of the TXT record to query.
        :return: List of strings stored in the TXT record.
        """
        txt_records = []

        with contextlib.suppress(
            dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer
        ):
            resp = await self._resolver.resolve(name, "TXT")

            for records in resp.rrset.items.keys():
                txt_records.extend([record.decode() for record in records.strings])

        return txt_records

    async def _query_until_completed(self, name, text):
        while True:
            records = await self.query_txt_record(name)

            if text in records:
                return

            logger.debug(
                f"{name} does not have TXT {text} yet. Retrying (Records: {records}"
            )
            await asyncio.sleep(1.0)

    async def complete_challenge(
        self,
        key: josepy.jwk.JWKRSA,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
        """Complete the given DNS-01 challenge.

        This method provisions the TXT record needed to complete the given challenge.
        Then it polls the DNS for up to 60 seconds to ensure that the record is visible
        to the remote CA's DNS.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to be completed.
        :raises: :class:`asyncio.TimeoutError` If the challenge completion attempt timed out.
        """
        name = challenge.chall.validation_domain_name(identifier.value)
        text = challenge.chall.validation(key)

        await self.set_txt_record(name, text)

        # Poll the DNS until the correct record is available
        await asyncio.wait_for(self._query_until_completed(name, text), 60.0)
