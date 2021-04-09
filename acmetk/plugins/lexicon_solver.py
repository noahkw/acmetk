import asyncio
import logging
import functools
import typing
import importlib

import dns.name
import acme.messages
from requests.exceptions import HTTPError, RequestException
import josepy.jwk
from lexicon.providers.base import Provider as BaseProvider
from lexicon.config import ConfigResolver

from acmetk.client import CouldNotCompleteChallenge
from acmetk.client.challenge_solver import DNSSolver
from acmetk.plugin_base import PluginRegistry

logger = logging.getLogger(__name__)

"""This module contains a DNS challenge solver based on the lexicon library.
"""


@PluginRegistry.register_plugin("lexicon")
class LexiconChallengeSolver(DNSSolver):
    def __init__(self, provider_name=None, provider_options=None):
        try:
            provider_module = importlib.import_module(
                "lexicon.providers." + provider_name
            )
        except Exception as e:
            print(e)
        self.providing: typing.Type[BaseProvider] = getattr(provider_module, "Provider")

        config: typing.Dict[str, typing.Any] = {
            "provider_name": provider_name,
            "domain": "..invalid..",
        }
        provider_config = {}
        provider_config.update(provider_options)
        config[provider_name] = provider_config
        self.config = ConfigResolver().with_dict(config)

        super().__init__()

    @staticmethod
    async def _find_domain_id(provider, domain):
        """
        Find the domain_id for a given domain.

        :param str domain: The domain for which to find the domain_id.
        :raises errors.PluginError: if the domain_id cannot be found.
        """

        name = dns.name.from_text(domain)
        domain_name_guesses = [
            name.split(i)[1].to_text(omit_final_dot=1)
            for i in range(2, len(name.labels) + 1)
        ]
        for domain_name in domain_name_guesses:
            provider.domain = domain_name
            try:
                provider.authenticate()
                return
            except HTTPError as e0:
                raise e0
            except Exception as e1:
                if str(e1).startswith("No domain found"):
                    return
                raise e1
        raise ValueError(
            "Unable to determine zone identifier for {0} using zone names: {1}".format(
                domain, domain_name_guesses
            )
        )

    async def set_txt_record(
        self, provider: BaseProvider, name: str, text: str, views=None, ttl: int = 60
    ):
        """Sets a DNS TXT record.

        :param provider: The Lexicon Provider.
        :param name: The name of the TXT record.
        :param text: The text of the TXT record.
        :param views: List of views to set the TXT record in. Defaults to *Intern* and *Extern*.
        :param ttl: Time to live of the TXT record in seconds.
        """
        logger.debug("Setting TXT record %s = %s, TTL %d", name, text, ttl)

        await self._find_domain_id(provider, name)

        try:
            await asyncio.gather(
                *[
                    self._loop.run_in_executor(
                        None,
                        functools.partial(
                            provider.create_record, rtype="TXT", name=name, content=text
                        ),
                    )
                ]
            )
        except RequestException as e:
            logger.debug("Encountered error adding TXT record: %s", e, exc_info=True)
            raise ValueError("Error adding TXT record: {0}".format(e))

    async def delete_txt_record(self, provider: BaseProvider, name: str, text: str):
        """Deletes a DNS TXT record.

        :param provider: The Lexicon Provider.
        :param name: The name of the TXT record to delete.
        :param text: The text of the TXT record to delete.
        """
        logger.debug("Deleting TXT record %s = %s", name, text)

        try:
            await asyncio.gather(
                *[
                    self._loop.run_in_executor(
                        None,
                        functools.partial(
                            provider.delete_record,
                            rtype="TXT",
                            name=name,
                            content=text,
                        ),
                    )
                ]
            )
        except RequestException as e:
            logger.debug("Encountered error deleting TXT record: %s", e, exc_info=True)

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

        provider = self.providing(self.config)

        try:
            await self._find_domain_id(provider, name)
        except Exception as e:
            logger.exception(e)

        try:
            await self.set_txt_record(provider, name, text)
        except Exception as e:
            logger.exception(
                "Could not set TXT record to solve challenge: %s = %s", name, text
            )
            raise CouldNotCompleteChallenge(
                challenge,
                acme.messages.Error(typ="lexicon", title="error", detail=str(e)),
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
                    typ="lexicon",
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
        provider = self.providing(self.config)

        name = challenge.chall.validation_domain_name(identifier.value)
        text = challenge.chall.validation(key)
        try:
            await self._find_domain_id(provider, name)
            await self.delete_txt_record(provider, name, text)
        except Exception as e:
            logger.exception(e)
