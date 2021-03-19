from acmetk.server.challenge_validator import ChallengeValidator
from acmetk.plugin_base import PluginRegistry

"""This module contains a template challenge validator plugin that is automatically loaded by the main CLI script.
"""


@PluginRegistry.register_plugin("templatevalidator")
class TemplateValidator(ChallengeValidator):
    pass

    # async def validate_challenge(self, challenge: Challenge, **kwargs):
    #     pass
