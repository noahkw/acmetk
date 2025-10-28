import asyncio
import logging
import functools
import typing

import acme.messages
import asyncache
import cachetools
import dns.name
import dns.asyncresolver
import josepy.jwk

from requests.exceptions import HTTPError, RequestException

from acmetk.client.exceptions import CouldNotCompleteChallenge
from acmetk.client.challenge_solver import ChallengeSolver
from acmetk.util import DNS01ChallengeHelper
from acmetk.plugin_base import PluginRegistry

logger = logging.getLogger(__name__)

try:
    import lexicon
    import lexicon.client
    from lexicon.config import ConfigResolver, DictConfigSource
    from lexicon.exceptions import AuthenticationError, LexiconError
except ImportError:
    logger.warning("Lexicon client not available.")


"""This module contains a DNS challenge solver based on the lexicon library.
"""


@PluginRegistry.register_plugin("lexicon")
class LexiconChallengeSolver(DNS01ChallengeHelper, ChallengeSolver):
    class Config(DNS01ChallengeHelper.Config, ChallengeSolver.Config):
        type: typing.Literal["lexicon"] = "lexicon"
        provider_name: str
        """
        lexicon provider name
        """
        provider_options: dict[str, typing.Any]
        """
        lexicon provider options
        """

    def __init__(self, cfg: Config):
        super().__init__(cfg=cfg, helper=cfg)

        self.config: dict[str, typing.Any] = {
            "provider_name": cfg.provider_name,
            cfg.provider_name: cfg.provider_options.copy() if cfg.provider_options else {},
        }
        self.provider_name = cfg.provider_name

    async def _config_for(self, name: str) -> "ConfigResolver":
        zone = await dns.asyncresolver.zone_for_name(name)
        cfg = ConfigResolver().with_dict(self.config)
        cfg.add_config_source(DictConfigSource({"domain": name, "ddns": {"domain": zone.to_text()}}), 0)
        return cfg

    @asyncache.cached(
        cache=cachetools.LRUCache(maxsize=32),
        key=lambda _self, provider, domain: domain.lower(),
    )
    async def _find_domain_id(self, provider, domain):
        """
        Find the domain_id for a given domain.

        :param str domain: The domain for which to find the domain_id.
        :raises errors.PluginError: if the domain_id cannot be found.
        """

        name = dns.name.from_text(domain)
        domain_name_guesses = [name.split(i)[1].to_text(omit_final_dot=1) for i in range(2, len(name.labels) + 1)]
        for domain_name in domain_name_guesses:
            provider.domain = domain_name
            try:
                await asyncio.gather(*[self._loop.run_in_executor(None, provider.authenticate)])
                return domain_name
            except AuthenticationError:
                # Authentication failed … continue guessing
                continue
            except (LexiconError, HTTPError) as e0:
                logger.warning("lexicon failed with %s", str(e0))
                raise e0
            except Exception as e1:
                logger.warning("lexicon failed with %s", str(e1))
                raise e1
        raise ValueError(f"Unable to determine zone identifier for {domain} using zone names: {domain_name_guesses}")

    async def set_txt_record(
        self,
        ops: "lexicon.client._ClientOperations",
        name: str,
        text: str,
        views=None,
        ttl: int = 60,
    ):
        """Sets a DNS TXT record.

        :param ops: The Lexicon Client operations.
        :param name: The name of the TXT record.
        :param text: The text of the TXT record.
        :param views: List of views to set the TXT record in. Defaults to *Intern* and *Extern*.
        :param ttl: Time to live of the TXT record in seconds.
        """
        logger.debug("Setting TXT record %s = %s, TTL %d", name, text, ttl)

        try:
            await asyncio.gather(
                *[
                    self._loop.run_in_executor(
                        None,
                        functools.partial(ops.create_record, rtype="TXT", name=name, content=text),
                    )
                ]
            )
        except RequestException as e:
            logger.debug("Encountered error adding TXT record: %s", e, exc_info=True)
            raise ValueError(f"Error adding TXT record: {e}")

    async def delete_txt_record(self, ops: "lexicon.client._ClientOperations", name: str, text: str):
        """Deletes a DNS TXT record.

        :param ops: The Lexicon Client operations.
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
                            ops.delete_record,
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
        cfg = await self._config_for(name)

        try:
            with lexicon.client.Client(cfg) as ops:
                await self.set_txt_record(ops, name, text)
        except Exception as e:
            logger.exception("Could not set TXT record to solve challenge: %s = %s", name, text)
            raise CouldNotCompleteChallenge(
                challenge,
                acme.messages.Error(typ="lexicon", title="error", detail=str(e)),
            )

        # Poll the DNS until the correct record is available
        try:
            await asyncio.wait_for(self._query_until_completed(name, text), self.POLLING_TIMEOUT)
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

        name = challenge.chall.validation_domain_name(identifier.value)
        text = challenge.chall.validation(key)

        cfg = await self._config_for(name)

        try:
            #            provider.domain = await self._find_domain_id(provider, name)
            with lexicon.client.Client(cfg) as ops:
                assert ops.provider.zone is not None, ops.provider.zone
                assert ops.provider.domain
                await self.delete_txt_record(ops, name, text)
        except Exception as e:
            logger.exception(e)
