import abc
import asyncio
import enum
import functools
import logging

import dns.asyncresolver
from infoblox_client import connector, objects


logger = logging.getLogger(__name__)


class ChallengeSolverType(enum.Enum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    TLS_ALPN_01 = "tls-alpn-01"


class ChallengeSolver(abc.ABC):
    @abc.abstractmethod
    async def complete_challenge(self, key, identifier, challenge):
        """Complete the given challenge.

        This method should complete the given challenge and then delay
        returning until the server is allowed to check for completion.

        :param challenge: The challenge to be completed
        :type challenge: acme.messages.ChallengeBody
        """
        pass


class DummySolver(ChallengeSolver):
    async def complete_challenge(self, key, identifier, challenge):
        logger.debug(
            f"(not) solving challenge {challenge.uri}, type {challenge.chall.typ}, identifier {identifier}"
        )
        # await asyncio.sleep(1)


class InfobloxClient(ChallengeSolver):
    POLLING_DELAY = 1.0  # time in seconds between consecutive DNS requests
    POLLING_TIMEOUT = (
        60.0  # time in seconds after which placing the TXT record is considered failed
    )

    def __init__(self, *, host, username, password):
        self._creds = {"host": host, "username": username, "password": password}
        self._loop = asyncio.get_event_loop()

    async def connect(self):
        self._conn = await self._loop.run_in_executor(
            None, connector.Connector, self._creds
        )

    async def set_txt_record(self, name, text, views=None, ttl=60):
        if views is None:
            views = ("Intern", "Extern")

        logger.debug("Setting TXT record %s = %s, TTL %d", name, text, ttl)

        # TODO: error handling
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

    async def query_txt_record(self, name):
        resp = await dns.asyncresolver.resolve(name, "TXT")
        logger.debug(resp.response.answer)
        txt_record = list(resp.rrset.items.items())[0][0]

        return txt_record.strings[0].decode()

    async def _query_until_completed(self, name, text):
        while True:
            actual_text = await self.query_txt_record(name)
            await asyncio.sleep(1.0)
            if actual_text == text:
                return

    async def complete_challenge(self, key, identifier, challenge):
        name = challenge.chall.validation_domain_name(identifier.value)
        text = challenge.chall.validation(key)

        await self.set_txt_record(name, text)

        # Poll the DNS until the correct record is available
        await asyncio.wait_for(self._query_until_completed(name, text), 60.0)
