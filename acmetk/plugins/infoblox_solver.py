import asyncio
import logging
import functools

import acme.messages
import josepy.jwk

from infoblox_client import connector, objects

from acmetk.client import CouldNotCompleteChallenge
from acmetk.client.challenge_solver import DNSSolver
from acmetk.plugin_base import PluginRegistry

logger = logging.getLogger(__name__)

"""This module contains a DNS challenge solver based on the infoblox_client library.
"""


@PluginRegistry.register_plugin("infoblox")
class InfobloxClient(DNSSolver):
    """InfoBlox DNS-01 challenge solver.

    This challenge solver connects to an InfoBlox API to provision
    DNS TXT records in order to complete the ACME DNS-01 challenge type.
    """

    DEFAULT_VIEWS = ["Extern"]
    """The views to use if none are specified during initialization."""

    def __init__(self, *, host, username, password, dns_servers=None, views=None):
        self._creds = {
            "host": host,
            "username": username,
            "password": password,
            "ssl_verify": True,
        }
        self._conn = None
        self._views = views or self.DEFAULT_VIEWS

        super().__init__(dns_servers=dns_servers)

    async def _connect(self):
        """Connects to the InfoBlox API.

        This method must be called before attempting to complete challenges.
        """
        if not self._conn:
            self._conn = await self._loop.run_in_executor(
                None, connector.Connector, self._creds
            )

    async def set_txt_record(self, name: str, text: str, views=None, ttl: int = 60):
        """Sets a DNS TXT record.

        :param name: The name of the TXT record.
        :param text: The text of the TXT record.
        :param views: List of views to set the TXT record in. Defaults to *Intern* and *Extern*.
        :param ttl: Time to live of the TXT record in seconds.
        """
        views = views or self._views

        logger.debug("Setting TXT record %s = %s, TTL %d", name, text, ttl)

        # Infoblox-client exceptions are propagated.
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

    async def delete_txt_record(self, name: str, text: str):
        """Deletes a DNS TXT record.

        :param name: The name of the TXT record to delete.
        :param text: The text of the TXT record to delete.
        """
        logger.debug("Deleting TXT record %s = %s", name, text)

        # Fetch all TXT records of the given name that contain the given text.
        records = await self._loop.run_in_executor(
            None,
            functools.partial(
                objects.TXTRecord.search_all, self._conn, name=name, text=text
            ),
        )

        # De-provision those TXT records
        await asyncio.gather(
            *[self._loop.run_in_executor(None, record.delete) for record in records]
        )

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

        try:
            await self._connect()
            await self.set_txt_record(name, text)
        except Exception as e:
            logger.exception(
                "Could not set TXT record to solve challenge: %s = %s", name, text
            )
            raise CouldNotCompleteChallenge(
                challenge,
                acme.messages.Error(typ="infoblox", title="error", detail=str(e)),
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
                    typ="infoblox",
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

        await self._connect()
        await self.delete_txt_record(name, text)
