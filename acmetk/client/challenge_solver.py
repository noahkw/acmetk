import abc
import logging
import typing

import acme.messages
import josepy
from pydantic_settings import BaseSettings

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

    class Config(BaseSettings, extra="forbid"):
        type: typing.Literal["none"] = "none"

    def __init__(self, cfg: Config):
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

    class Config(ChallengeSolver.Config):
        type: typing.Literal["dummy"] = "dummy"

    async def complete_challenge(
        self,
        key: josepy.jwk.JWK,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ) -> None:
        """Does not complete the given challenge.

        Instead, this method only logs the mock completion attempt and pauses
        execution for one second.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to be completed.
        """
        logger.debug(f"(not) solving challenge {challenge.uri}, type {challenge.chall.typ}, identifier {identifier}")
        # await asyncio.sleep(1)

    async def cleanup_challenge(
        self,
        key: josepy.jwk.JWK,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ) -> None:
        """Performs cleanup for the given challenge.

        Does not actually do any cleanup, instead it just logs the mock attempt and pauses execution
        for one second.

        :param key: The client's account key.
        :param identifier: The identifier that is associated with the challenge.
        :param challenge: The challenge to clean up after.
        """
        logger.debug(f"(not) cleaning up after challenge {challenge.uri}, type {challenge.chall.typ}")
