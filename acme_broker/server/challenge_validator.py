import abc
import logging
import typing

from acme_broker import models

logger = logging.getLogger(__name__)


class CouldNotValidateChallenge(Exception):
    pass


class ChallengeValidator(abc.ABC):
    SUPPORTED_CHALLENGES: typing.Iterable[models.ChallengeType]

    @abc.abstractmethod
    async def validate_challenge(self, challenge):
        """Validate the given challenge.

        This method should attempt to validate the given challenge and
        raise a CouldNotValidateChallenge exception if it did not succeed.

        :param challenge: The challenge to be validated
        :type challenge: acme_broker.models.Challenge
        """
        pass


class RequestIPDNSChallengeValidator(ChallengeValidator):
    """Validator for the Request IP DNS challenge.

    This validator does not actually validate a challenge defined by
    the ACME protocol. Instead, it checks whether the corresponding
    authorization's identifier resolves to the IP that the validation
    request is being made from by checking for a A/AAAA record.
    """

    SUPPORTED_CHALLENGES = frozenset(
        [models.ChallengeType.DNS_01, models.ChallengeType.HTTP_01]
    )

    async def validate_challenge(self, challenge):
        pass


class DummyValidator(ChallengeValidator):
    """Does not do any validation and reports every challenge as valid."""

    SUPPORTED_CHALLENGES = frozenset(
        [models.ChallengeType.DNS_01, models.ChallengeType.HTTP_01]
    )

    async def validate_challenge(self, challenge):
        pass
