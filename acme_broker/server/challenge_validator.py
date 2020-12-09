import abc
import contextlib
import ipaddress
import itertools
import logging
import typing
import dns.asyncresolver

from acme_broker.models import ChallengeType, Challenge
from acme_broker.util import ConfigurableMixin

logger = logging.getLogger(__name__)


class CouldNotValidateChallenge(Exception):
    """Exception that is raised when any given challenge could not be validated."""

    pass


class ChallengeValidator(ConfigurableMixin, abc.ABC):
    """An abstract base class for challenge validator clients.

    All challenge validator implementations must implement the method :func:`validate_challenge`
    that validates the given challenge.
    Implementations must also set the :attr:`config_name` attribute, so that the CLI script knows which
    configuration option corresponds to which challenge validator class.
    """

    config_name: str
    """The string that maps to the validator implementation inside configuration files."""

    SUPPORTED_CHALLENGES: typing.Iterable[ChallengeType]
    """The types of challenges that the challenge validator implementation supports."""

    subclasses = []

    @abc.abstractmethod
    async def validate_challenge(self, challenge: Challenge, **kwargs):
        """Validates the given challenge.

        This method should attempt to validate the given challenge and
        raise a :class:`CouldNotValidateChallenge` exception if the validation failed.

        :param challenge: The challenge to be validated
        :raises: :class:`CouldNotValidateChallenge` If the validation failed
        """
        pass


class RequestIPDNSChallengeValidator(ChallengeValidator):
    """Validator for the Request IP DNS challenge.

    This validator does not actually validate a challenge defined by
    the ACME protocol. Instead, it checks whether the corresponding
    authorization's identifier resolves to the IP that the validation
    request is being made from by checking for a A/AAAA record.
    """

    config_name = "requestipdns"

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.DNS_01, ChallengeType.HTTP_01])
    """The types of challenges that the validator supports."""

    async def _query_record(self, name, type_):
        resolved_ips = []

        with contextlib.suppress(
            dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer
        ):
            resp = await dns.asyncresolver.resolve(name, type_)
            resolved_ips.extend(
                [
                    ipaddress.ip_address(record.address)
                    for record in resp.rrset.items.keys()
                ]
            )

        return resolved_ips

    async def query_records(self, name: str) -> typing.Set[str]:
        """Queries DNS A and AAAA records.

        :param name: Name of the A/AAAA record to query.
        :return: Set of IPs that the A/AAAA records resolve to.
        """
        resolved_ips = [
            await self._query_record(name, type_) for type_ in ("A", "AAAA")
        ]

        return set(itertools.chain.from_iterable(resolved_ips))

    async def validate_challenge(self, challenge: Challenge, request=None):
        """Validates the given challenge.

        This method takes a challenge of :class:`ChallengeType` *DNS_01* or *HTTP_01*
        and does not actually validate that challenge, but instead checks whether the corresponding
        authorization's identifier resolves to the IP address that the validation request is being made from.

        :param challenge: The challenge to be validated
        :raises: :class:`CouldNotValidateChallenge` If the validation failed
        """
        identifier = challenge.authorization.identifier.value
        logger.debug(
            "Validating challenge %s for identifier %s",
            challenge.challenge_id,
            identifier,
        )

        resolved_ips = await self.query_records(identifier)

        if request["actual_ip"] not in resolved_ips:
            raise CouldNotValidateChallenge


class DummyValidator(ChallengeValidator):
    """Does not do any validation and reports every challenge as valid."""

    config_name = "dummy"

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.DNS_01, ChallengeType.HTTP_01])
    """The types of challenges that the validator supports."""

    async def validate_challenge(self, challenge: Challenge, **kwargs):
        """Does not validate the given challenge.

        Instead, this method only logs the mock validation attempt and pauses
        execution for one second.

        :param challenge: The challenge to be validated
        """
        logger.debug(
            f"(not) validating challenge {challenge.challenge_id}, type {challenge.type}"
        )
        # await asyncio.sleep(1)
