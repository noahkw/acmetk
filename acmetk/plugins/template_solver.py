from acmetk.client.challenge_solver import ChallengeSolver
from acmetk.plugin_base import PluginRegistry

"""This module contains a template challenge solver plugin that is automatically loaded by the main CLI script.
"""


@PluginRegistry.register_plugin("templatesolver")
class TemplateSolver(ChallengeSolver):
    pass

    # async def connect(self):
    #     pass
    #
    # @abc.abstractmethod
    # async def complete_challenge(
    #     self,
    #     key: josepy.jwk.JWK,
    #     identifier: acme.messages.Identifier,
    #     challenge: acme.messages.ChallengeBody,
    # ):
    #     pass
    #
    # @abc.abstractmethod
    # async def cleanup_challenge(
    #     self,
    #     key: josepy.jwk.JWK,
    #     identifier: acme.messages.Identifier,
    #     challenge: acme.messages.ChallengeBody,
    # ):
    #     pass
