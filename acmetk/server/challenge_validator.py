import abc
import asyncio
import contextlib
import hashlib
import ipaddress
import itertools
import logging
import random
import ssl
import string
import typing

import acme.messages
import aiohttp.web
from cryptography import x509
import dns.asyncresolver
import yarl

from acmetk.models import ChallengeType, Challenge
from acmetk.plugin_base import PluginRegistry

logger = logging.getLogger(__name__)


class CouldNotValidateChallenge(Exception):
    """Exception that is raised when any given challenge could not be validated."""

    def __init__(self, *args, detail=None):
        super().__init__(*args)
        self.detail = detail

    def to_acme_error(self):
        return acme.messages.Error(
            typ="CouldNotValidateChallenge",
            title="Challenge validation failed",
            detail=self.detail,
        )


class ChallengeValidator(abc.ABC):
    """An abstract base class for challenge validator clients.

    All challenge validator implementations must implement the method :func:`validate_challenge`
    that validates the given challenge.
    Implementations must also be registered with the plugin registry via
    :meth:`~acmetk.plugin_base.PluginRegistry.register_plugin`, so that the CLI script knows which configuration
    option corresponds to which challenge validator class.
    """

    SUPPORTED_CHALLENGES: typing.Iterable[ChallengeType]
    """The types of challenges that the challenge validator implementation supports."""

    @abc.abstractmethod
    async def validate_challenge(self, challenge: Challenge, **kwargs):
        """Validates the given challenge.

        This method should attempt to validate the given challenge and
        raise a :class:`CouldNotValidateChallenge` exception if the validation failed.

        :param challenge: The challenge to be validated
        :raises: :class:`CouldNotValidateChallenge` If the validation failed
        """
        pass


@PluginRegistry.register_plugin("http01")
class Http01ChallengeValidator(ChallengeValidator):
    DEFAULT_PORT: int = 80
    SUPPORTED_CHALLENGES = frozenset([ChallengeType.HTTP_01])
    """The types of challenges that the validator supports."""

    def __init__(self, port: int = 80) -> None:
        super().__init__()
        self._port = port
        """Choosing the port is required for unit testing."""

    async def validate_challenge(
        self, challenge: Challenge, request: aiohttp.web.Request = None
    ):
        """Validates the given challenge.

        This method takes a challenge of :class:`ChallengeType` *HTTP_01*
        and validates according to it.

        :param challenge: The challenge to be validated
        :param request: The request to be validated
        :raises: :class:`CouldNotValidateChallenge` If the validation failed
        """
        identifier = challenge.authorization.identifier.value
        logger.debug(
            "Validating %s challenge %s for identifier %s",
            challenge.type,
            challenge.challenge_id,
            identifier,
        )

        try:
            async with aiohttp.ClientSession() as session:
                url = yarl.URL(
                    f"http://{identifier}/.well-known/acme-challenge/{challenge.token}"
                )
                if self._port != self.DEFAULT_PORT:
                    url = url.with_port(self._port)
                async with session.get(url) as response:
                    if response.status != 200:
                        raise CouldNotValidateChallenge(
                            detail=f"Validation of challenge {challenge.challenge_id} failed; "
                            f"http_status {response.status}"
                        )
                    data = await response.text()
                    if data != challenge.keyAuthorization:
                        raise CouldNotValidateChallenge(
                            detail=f"Validation of challenge {challenge.challenge_id} failed; "
                            f"token mismatch {challenge.keyAuthorization} != {data}"
                        )
        except Exception as e:
            raise CouldNotValidateChallenge(
                detail=f"Validation of challenge {challenge.challenge_id} failed; {e}"
            )


@PluginRegistry.register_plugin("tlsalpn01")
class TLSALPN01ChallengeValidator(ChallengeValidator):
    PE_ACMEIDENTIFIER = "1.3.6.1.5.5.7.1.31"
    """OID for the Certificate Extension"""

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.TLS_ALPN_01])
    """The types of challenges that the validator supports."""

    def __init__(self, port: int = 443) -> None:
        super().__init__()
        self._port = port
        """Choosing the port is required for unit testing."""

    async def validate_challenge(
        self, challenge: Challenge, request: aiohttp.web.Request = None
    ):
        """Validates the given challenge.

        This method takes a challenge of :class:`ChallengeType` *HTTP_01*
        and validates according to it.

        :param challenge: The challenge to be validated
        :param request: The request to be validated
        :raises: :class:`CouldNotValidateChallenge` If the validation failed
        """
        identifier = challenge.authorization.identifier.value
        logger.debug(
            "Validating %s challenge %s for identifier %s",
            challenge.type,
            challenge.challenge_id,
            identifier,
        )

        try:
            reader, writer = await asyncio.open_connection(identifier, self._port)

            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            ctx.set_alpn_protocols(["acme-tls/1"])
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            await writer.start_tls(ctx, server_hostname=identifier)

            cert: x509.Certificate = x509.load_der_x509_certificate(
                writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            )

            logger.debug(f"The server certificate is {cert.subject.rfc4514_string()}")

            ext = cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(self.PE_ACMEIDENTIFIER)
            )
            value: bytes = ext.value.value[2:]
            expect = hashlib.sha256(challenge.keyAuthorization.encode()).digest()
            if value != expect:
                raise ValueError((expect.hex(sep=":"), value.hex(sep=":")))
        except Exception as e:
            raise CouldNotValidateChallenge(
                detail=f"Validation of challenge {challenge.challenge_id} failed; {e}"
            )


@PluginRegistry.register_plugin("requestipdns")
class RequestIPDNSChallengeValidator(ChallengeValidator):
    """Validator for the Request IP DNS challenge.

    This validator does not actually validate a challenge defined by
    the ACME protocol. Instead, it checks whether the corresponding
    authorization's identifier resolves to the IP that the validation
    request is being made from by checking for a A/AAAA record.
    """

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.DNS_01, ChallengeType.HTTP_01])
    """The types of challenges that the validator supports."""

    async def _query_record(self, name: str, type_: typing.Literal["A", "AAAA"]):
        resolved_ips = []

        with contextlib.suppress(
            dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer
        ):
            resp = await dns.asyncresolver.resolve(name, type_)
            resolved_ips.extend(
                [
                    ipaddress.ip_address(record.address)
                    for record in resp.rrset.items.keys()
                ]
            )

        return resolved_ips

    async def query_records(self, name: str) -> set[str]:
        """Queries DNS A and AAAA records.

        :param name: Name of the A/AAAA record to query.
        :return: Set of IPs that the A/AAAA records resolve to.
        """
        resolved_ips = [
            await self._query_record(name, type_) for type_ in ("A", "AAAA")
        ]

        return set(itertools.chain.from_iterable(resolved_ips))

    async def validate_challenge(
        self, challenge: Challenge, request: aiohttp.web.Request = None
    ):
        """Validates the given challenge.

        This method takes a challenge of :class:`ChallengeType` *DNS_01* or *HTTP_01*
        and does not actually validate that challenge, but instead checks whether the corresponding
        authorization's identifier resolves to the IP address that the validation request is being made from.

        :param challenge: The challenge to be validated
        :param request: The request to be validated
        :raises: :class:`CouldNotValidateChallenge` If the validation failed
        """
        identifier = challenge.authorization.identifier.value
        logger.debug(
            "Validating %s challenge %s for identifier %s by requestipdns",
            challenge.type,
            challenge.challenge_id,
            identifier,
        )

        """Wildcard validation …
        Resolve some names
        """
        if challenge.authorization.wildcard:
            identifier = identifier[2:]
            names = ["www", "mail", "smtp", "gitlab"]
            rnames = [
                "".join([random.choice(string.ascii_lowercase) for j in range(i)])
                for i in range(6)
            ]
            names.extend(rnames)
            resolved = await asyncio.gather(
                *[self.query_records(f"{i}.{identifier}") for i in names]
            )
            resolved_ips = set.intersection(*resolved)
        else:
            resolved_ips = await self.query_records(identifier)

        actual_ip = request["actual_ip"]
        if actual_ip not in resolved_ips:
            logger.debug(
                "Validation of challenge %s failed; %s does not resolve to IP %s. Resolved IPs: %s",
                challenge.challenge_id,
                identifier,
                actual_ip,
                resolved_ips,
            )

            raise CouldNotValidateChallenge(
                detail=f"Identifier '{identifier}' does not resolve to host IP '{actual_ip}'."
            )


@PluginRegistry.register_plugin("dummy")
class DummyValidator(ChallengeValidator):
    """Does not do any validation and reports every challenge as valid."""

    SUPPORTED_CHALLENGES = frozenset([ChallengeType.DNS_01, ChallengeType.HTTP_01])
    """The types of challenges that the validator supports."""

    async def validate_challenge(self, challenge: Challenge, **kwargs):
        """Does not validate the given challenge.

        Instead, this method only logs the mock validation attempt and pauses
        execution for one second.

        :param challenge: The challenge to be validated
        """
        identifier = challenge.authorization.identifier.value
        logger.debug(
            "Validating %s challenge %s for identifier %s (not)",
            challenge.type,
            challenge.challenge_id,
            identifier,
        )

        # await asyncio.sleep(1)
