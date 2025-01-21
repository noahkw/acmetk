import asyncio
import logging

import acme.messages
import dns.asyncresolver
import dns.tsigkeyring
import dns.update
import josepy.jwk

from acmetk.client import CouldNotCompleteChallenge
from acmetk.client.challenge_solver import ChallengeSolver
from acmetk.util import DNS01ChallengeHelper
from acmetk.plugin_base import PluginRegistry

logger = logging.getLogger(__name__)

"""
This module contains a DNS challenge solver using RFC2136 TSIG updates

It looks up the zone name using the TSIG credentials on the resolver
"""


@PluginRegistry.register_plugin("rfc2136")
class RFC2136Client(DNS01ChallengeHelper, ChallengeSolver):
    def __init__(self, server: str, keyid: str, alg: str, secret: str):
        super().__init__()
        self.keyring = dns.tsigkeyring.from_text({keyid: (alg, secret)})

        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = [server]
        self.resolver.keyring = self.keyring
        self.resolver.keyname = keyid
        self.resolver.keyalgorithm = alg

    async def _run_query(self, msg):
        await dns.asyncquery.tcp(q=msg, where=self.resolver.nameservers[0])

    async def _update(self, name: str):
        zone = await dns.asyncresolver.zone_for_name(name, resolver=self.resolver)
        name = dns.name.from_text(name).relativize(zone)

        update = dns.update.Update(zone, keyring=self.keyring)
        return name, update

    async def set_txt_record(self, name: str, text: str, views=None, ttl: int = 60):
        logger.debug("Setting TXT record %s = %s, TTL %d", name, text, ttl)

        name, update = await self._update(name)
        update.add(name, ttl, "TXT", text)

        await self._run_query(update)

    async def delete_txt_record(self, name: str, text: str):
        logger.debug("Deleting TXT record %s = %s", name, text)

        name, update = await self._update(name)
        update.delete(name, "TXT", text)

        await self._run_query(update)

    async def complete_challenge(
        self,
        key: josepy.jwk.JWK,
        identifier: acme.messages.Identifier,
        challenge: acme.messages.ChallengeBody,
    ):
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
                acme.messages.Error(typ="rfc2136", title="error", detail=str(e)),
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
                    typ="rfc2136",
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
        name = challenge.chall.validation_domain_name(identifier.value)
        text = challenge.chall.validation(key)

        await self.delete_txt_record(name, text)
