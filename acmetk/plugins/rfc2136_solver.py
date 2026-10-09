import asyncio
import logging
import random
import typing

import acme.messages
import dns.asyncresolver
import dns.message
import dns.tsigkeyring
import dns.update
import josepy.jwk

from acmetk.client.challenge_solver import ChallengeSolver
from acmetk.client.exceptions import CouldNotCompleteChallenge
from acmetk.plugin_base import PluginRegistry
from acmetk.util import DNS01ChallengeHelper

logger = logging.getLogger(__name__)

"""
This module contains a DNS challenge solver using RFC2136 TSIG updates

It looks up the zone name using the TSIG credentials on the resolver
"""


@PluginRegistry.register_plugin("rfc2136")
class RFC2136Client(DNS01ChallengeHelper, ChallengeSolver):
    """
    Manages DNS-01 challenges using RFC 2136 dynamic updates.

    This class provides methods for setting up and removing TXT DNS records
    required to complete DNS-01 challenges as part of ACME (Automated Certificate
    Management Environment) protocol. It uses RFC 2136 for dynamic DNS updates and
    is intended to work with DNS servers supporting the specified protocol.
    """

    class Config(DNS01ChallengeHelper.Config, ChallengeSolver.Config):
        """
        Represents the configuration for the RFC2136 DNS challenge solver.

        This class inherits from `DNS01ChallengeHelper.Config` and
        `ChallengeSolver.Config` and is specifically designed to handle the
        configuration required for the RFC2136 DNS challenge solver. It includes
        attributes to define server details, authentication credentials, and other
        necessary parameters.
        """

        type: typing.Literal["rfc2136"] = "rfc2136"
        """The type of challenge solver"""
        server: str
        """DNS server to use for TSIG updates"""
        keyid: str
        """TSIG key ID to use for TSIG updates"""
        alg: str
        """TSIG algorithm to use for TSIG updates"""
        secret: str
        """TSIG secret to use for TSIG updates"""

    def __init__(self, cfg: Config):
        super().__init__(cfg=cfg, helper=cfg)

        self.keyring = dns.tsigkeyring.from_text({cfg.keyid: (cfg.alg, cfg.secret)})
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = [cfg.server]
        self.resolver.keyring = self.keyring
        self.resolver.keyname = cfg.keyid
        self.resolver.keyalgorithm = cfg.alg
        self.__c: RFC2136Client.Config = cfg

    @staticmethod
    def _pretty(msg: dns.update.UpdateMessage) -> str:
        r = []
        zname = msg.zone[0].name.to_text(omit_final_dot=True)
        for rrset in msg.index.values():
            for rdata in rrset:
                t = dns.rdatatype.to_text(rrset.rdtype)
                if rrset.ttl == 0:
                    details = f"-{t}@{rrset.name}.{zname}={rdata}"
                else:
                    details = f"+{t}@{rrset.name}.{zname}={rdata}"

                r.append(details)
        return ",".join(r)

    async def _run_query(self, msg: dns.update.UpdateMessage):
        s: float = 0.0
        for i in range(5):
            r = await dns.asyncquery.tcp(q=msg, where=self.resolver.nameservers[0])
            if r.rcode() == dns.rcode.NOERROR:
                return
            s += random.randint(10, 30) / 10
            logger.info(f"{self._pretty(msg)} failed {r.rcode().name} (#{i}) sleep {s}")
            await asyncio.sleep(s)
        raise ValueError(f"{self._pretty(msg)} failed permanently")

    async def _update(self, name: str) -> tuple[dns.name.Name, dns.update.UpdateMessage]:
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
            logger.exception("Could not set TXT record to solve challenge: %s = %s", name, text)
            raise CouldNotCompleteChallenge(
                challenge,
                acme.messages.Error(typ="rfc2136", title="error", detail=str(e)),
            )

        # Poll the DNS until the correct record is available
        try:
            await asyncio.wait_for(self._query_until_completed(name, text), self.__c.polling_timeout)
        except TimeoutError:
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
