import abc
import asyncio
import contextlib
import functools
import logging
import typing

import acme.messages
import dns.asyncresolver
import josepy
from infoblox_client import connector, objects

from acmetk.client.exceptions import CouldNotCompleteChallenge
from acmetk.models import ChallengeType
from acmetk.plugin_base import PluginRegistry

logger = logging.getLogger(__name__)


class ChallengeSolver(abc.ABC):
    """An abstract base class for challenge solver clients.

    All challenge solver implementations must implement the methods :meth:`complete_challenge` and
    :func:`cleanup_challenge`.
    Implementations must also be registered with the plugin registry via
    :meth:`~acmetk.plugin_base.PluginRegistry.register_plugin`, so that the CLI script knows which configuration
    option corresponds to which challenge solver class.
    """

    SUPPORTED_CHALLENGES: typing.Iterable[ChallengeType]
    """The types of challenges that the challenge solver implementation supports."""

    async def connect(self):
        """Handles connecting the solver implementation to its remote API.

        Must not be overridden if no initial connection is required.
        """
        pass

    @abc.abstractmethod
    async def complete_challenge(
        self,
        key: josepy.jwk.JWK,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
        """Complete the given challenge.

        This method should complete the given challenge and then delay
        returning until the server is allowed to check for completion.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to be completed.
        :raises: :class:`~acmetk.client.exceptions.CouldNotCompleteChallenge`
            If the challenge completion attempt failed.
        """
        pass

    @abc.abstractmethod
    async def cleanup_challenge(
        self,
        key: josepy.jwk.JWK,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
        """Performs cleanup for the given challenge.

        This method should de-provision the resource that was provisioned for the given challenge.
        It is called once the challenge is complete, i.e. its status has transitioned to
        :class:`~acmetk.models.challenge.ChallengeStatus.VALID` or
        :class:`~acmetk.models.challenge.ChallengeStatus.INVALID`.

        This method should not assume that the challenge was successfully completed,
        meaning it should silently return if there is nothing to clean up.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to clean up after.
        """
        pass


@PluginRegistry.register_plugin("dummy")
class DummySolver(ChallengeSolver):
    """Dummy challenge solver that does not actually complete any challenges."""

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.DNS_01, ChallengeType.HTTP_01])
    """The types of challenges that the solver supports."""

    async def complete_challenge(
        self,
        key: josepy.jwk.JWK,
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

    async def cleanup_challenge(
        self,
        key: josepy.jwk.JWK,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
        """Performs cleanup for the given challenge.

        Does not actually do any cleanup, instead it just logs the mock attempt and pauses execution
        for one second.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to clean up after.
        """
        logger.debug(
            f"(not) cleaning up after challenge {challenge.uri}, type {challenge.chall.typ}"
        )


@PluginRegistry.register_plugin("infoblox")
class InfobloxClient(ChallengeSolver):
    """InfoBlox DNS-01 challenge solver.

    This challenge solver connects to an InfoBlox API to provision
    DNS TXT records in order to complete the ACME DNS-01 challenge type.
    """

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.DNS_01])
    """The types of challenges that the solver supports."""

    POLLING_DELAY = 1.0
    """Time in seconds between consecutive DNS requests."""

    POLLING_TIMEOUT = 60.0 * 5
    """Time in seconds after which placing the TXT record is considered a failure."""

    DEFAULT_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]
    """The DNS servers to use if none are specified during initialization."""

    DEFAULT_VIEWS = ["Extern"]
    """The views to use if none are specified during initialization."""

    def __init__(self, *, host, username, password, dns_servers=None, views=None):
        self._creds = {
            "host": host,
            "username": username,
            "password": password,
            "ssl_verify": True,
        }
        self._loop = asyncio.get_event_loop()

        self._resolvers = []

        for nameserver in dns_servers or self.DEFAULT_DNS_SERVERS:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = [nameserver]
            self._resolvers.append(resolver)

        self._views = views or self.DEFAULT_VIEWS

    async def connect(self):
        """Connects to the InfoBlox API.

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

    async def delete_txt_record(self, name: str, text: str):
        """Deletes a DNS TXT record.

        :param name: The name of the TXT record to delete.
        :param text: The text of the TXT record to delete.
        """
        logger.debug("Deleting TXT record %s = %s", name, text)

        # Fetch all TXT records of the given name that contain the given text.
        records = await self._loop.run_in_executor(
            None,
            functools.partial(
                objects.TXTRecord.search_all, self._conn, name=name, text=text
            ),
        )

        # De-provision those TXT records
        await asyncio.gather(
            *[self._loop.run_in_executor(None, record.delete) for record in records]
        )

    async def query_txt_record(
        self, resolver: dns.asyncresolver.Resolver, name: str
    ) -> typing.Set[str]:
        """Queries a DNS TXT record.

        :param name: Name of the TXT record to query.
        :return: Set of strings stored in the TXT record.
        """
        txt_records = []

        with contextlib.suppress(
            dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer
        ):
            resp = await resolver.resolve(name, "TXT")

            for records in resp.rrset.items.keys():
                txt_records.extend([record.decode() for record in records.strings])

        return set(txt_records)

    async def _query_until_completed(self, name, text):
        while True:
            record_sets = await asyncio.gather(
                *[self.query_txt_record(resolver, name) for resolver in self._resolvers]
            )

            # Determine set of records that has been seen by all name servers
            seen_by_all = set.intersection(*record_sets)

            if text in seen_by_all:
                return

            logger.debug(
                f"{name} does not have TXT {text} yet. Retrying (Records seen by all name servers: {seen_by_all}"
            )
            logger.debug(f"Records seen: {record_sets}")
            await asyncio.sleep(1.0)

    async def complete_challenge(
        self,
        key: josepy.jwk.JWK,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
        """Completes the given DNS-01 challenge.

        This method provisions the TXT record needed to complete the given challenge.
        Then it polls the DNS for up to :attr:`POLLING_TIMEOUT` seconds to ensure that the record is visible
        to the remote CA's DNS.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to be completed.
        :raises: :class:`~acmetk.client.exceptions.CouldNotCompleteChallenge`
            If the challenge completion attempt failed.
        """
        name = challenge.chall.validation_domain_name(identifier.value)
        text = challenge.chall.validation(key)

        try:
            await self.set_txt_record(name, text)
        except Exception as e:
            logger.exception(
                "Could not set TXT record to solve challenge: %s = %s", name, text
            )
            raise CouldNotCompleteChallenge(
                challenge,
                acme.messages.Error(typ="infoblox", title="error", detail=str(e)),
            )

        # Poll the DNS until the correct record is available
        try:
            await asyncio.wait_for(
                self._query_until_completed(name, text), self.POLLING_TIMEOUT
            )
        except asyncio.TimeoutError:
            raise CouldNotCompleteChallenge(
                challenge,
                acme.messages.Error(
                    typ="infoblox",
                    title="error",
                    detail="Could not complete challenge due to a DNS polling timeout",
                ),
            )

    async def cleanup_challenge(
        self,
        key: josepy.jwk.JWK,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
        """Performs cleanup for the given challenge.

        This method de-provisions the TXT record that was created to complete the given challenge.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to clean up after.
        """
        name = challenge.chall.validation_domain_name(identifier.value)
        text = challenge.chall.validation(key)

        await self.delete_txt_record(name, text)
