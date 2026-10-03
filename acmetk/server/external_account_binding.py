import datetime
import json
import typing
import urllib.parse

import acme.jws
import acme.messages
import aiohttp.web
import aiohttp_jinja2
import josepy
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic_settings import BaseSettings
from pydantic import Field

from acmetk.models.eab import EABCredential
from acmetk.server.routes import routes
from acmetk.util import url_for, forwarded_url

if typing.TYPE_CHECKING:
    import acmetk.server


class ExternalAccountBinding:
    """Represents an external account binding.

    `7.3.4. External Account Binding <https://tools.ietf.org/html/rfc8555#section-7.3.4>`_
    """

    def __init__(
        self,
        email: str,
        url: str,
        lifetime: datetime.timedelta,
        hmac_key: str | None = None,
    ):
        import secrets

        self.kid: str = email
        """The key identifier provided by the external binding mechanism."""
        self.url: str = url
        """The *newAccount* URL which is the same as in the encapsulating JWS."""
        self.hmac_key: str = secrets.token_urlsafe(32)
        """The key that is used to symmetrically sign the JWS."""
        self.when: datetime.datetime = datetime.datetime.now()
        """The time when the EAB request was created."""
        self.lifetime: datetime.timedelta = lifetime

    def expired(self) -> bool:
        """Returns whether the EAB has expired.

        :return: True iff the EAB has expired.
        """
        return datetime.datetime.now() - self.when > self.lifetime

    def _eab(self, key_json) -> acme.jws.JWS:
        decoded_hmac_key = josepy.b64.b64decode(self.hmac_key)
        return acme.jws.JWS.sign(
            key_json,
            josepy.jwk.JWKOct(key=decoded_hmac_key),
            josepy.jwa.HS256,
            None,
            self.url,
            self.kid,
        )

    def signature(self, key_json: str) -> str:
        """Returns the EAB's signature.

        :param key_json: The ACME account key that the external account is to be bound to.
        """
        return josepy.b64.b64encode(self._eab(key_json).signature.signature).decode()


class ExternalAccountBindingStore:
    """Database-backed store for EAB credentials.

    Mints new credential rows on `create()`, looks them up on `verify()`.
    Caller wires in the acmetk `Database` instance so we can open async sessions.
    """

    def __init__(self, db: "acmetk.database.Database"):
        self._db = db

    async def create(self, session, kid: str, url: str, lifetime: datetime.timedelta) -> EABCredential:
        """Mints (or refreshes) an EAB credential for the given kid.

        If a non-expired credential already exists for this kid, return it as-is.
        Otherwise insert a fresh one. Returns the :class:`~acmetk.models.eab.EABCredential`.
        :param url:
        """
        existing = await self._db.get_eab(session, kid)
        if existing is not None and not existing.expired():
            return existing

        if existing is not None:
            # Replace stale credential with a fresh pair
            await session.delete(existing)
            await session.flush()

        cred = EABCredential.create(kid, url, lifetime)
        session.add(cred)
        await session.commit()
        return await self._db.get_eab(session, kid)

    async def verify(
        self,
        kid: str,
        jws: acme.jws.JWS,
    ) -> bool:
        """Verifies an external account binding given its ACME account key, kid and signature.

        :param kid: The EAB's kid.
        :param jws: The EAB request JWS.
        :return: True iff verification was successful.
        """
        async with self._db.session() as session:
            cred = await self._db.get_eab(session, kid)
            if cred is None:
                return False
            if cred.expired():
                return False

            if ok := cred.verify(jws) and cred.consumed_at is None:
                cred.consumed_at = datetime.datetime.now(datetime.timezone.utc)
                await session.commit()
            return ok


def _email_from_request(request: aiohttp.web.Request, eab_type: typing.Literal["x509", "plain"], header: str) -> str:
    """Extract the contact email from a self-service ``/eab`` request, either via a
    plain header or by parsing an x509 client cert (mTLS flow). Raises :exc:`ValueError` if
    we cannot determine a unique email.

    :param request: The request that contains the PEM-encoded x509 client certificate in the *X-SSL-CERT* header.
    :param eab_type: The type of EAB authentication, either ``plain`` or ``x509``.
    :param header: The name of the header to read the email or certificate from.
    :return: The extracted email address.
    :raises ValueError: If the header is missing, the email cannot be determined uniquely,
        or an unknown ``eab_type`` is given.
    """
    value = request.headers.get(header)
    if value is None:
        raise ValueError(f"{header} header missing")

    match eab_type:
        case "plain":
            return value
        case "x509":
            # The client certificate in the PEM format (urlencoded) for an established SSL connection (1.13.5);
            cert = x509.load_pem_x509_certificate(urllib.parse.unquote(value).encode())
            mails: set[str] = set()
            nl = cert.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)
            if nl:
                mails |= {a.value for a in nl}
            try:
                ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san: x509.SubjectAlternativeName = ext.value
                mails |= set(san.get_values_for_type(x509.RFC822Name))
            except x509.ExtensionNotFound:
                pass

            if len(mails) != 1:
                raise ValueError(f"{len(mails)} mail addresses in cert, expecting 1 ({mails})")
            return mails.pop()
        case _:
            raise ValueError(f"unknown eab type: {eab_type!r}")


class AcmeEABMixin:
    """Mixin for an :class:`~acmetk.server.AcmeServerBase` implementation that provides external account
    binding creation and verification.

    `7.3.4. External Account Binding <https://tools.ietf.org/html/rfc8555#section-7.3.4>`_

    An external account binding request is created when the user visits the /eab route.
    The EAB mechanism used here is email verification using an SSL client certificate.
    A reverse proxy should be configured to include a set of root certificates that the user's browser
    can establish a chain of trust to.
    The reverse proxy then forwards the PEM and URL-encoded client certificate in the *X-SSL-CERT* header after
    verifying it.
    """

    SUPPORTED_EAB_JWS_ALGORITHMS: tuple[type]

    EXPIRE_DEFAULT = datetime.timedelta(hours=3)

    class Config(BaseSettings, extra="forbid"):
        required: bool = False
        type: typing.Literal["x509", "plain"] = "plain"
        header: str = "x-auth-request-email"
        """
        examples:
          for x509: ssl-client-cert
          for plain: x-auth-request-email
        """
        expires_after: datetime.timedelta = Field(default_factory=lambda: AcmeEABMixin.EXPIRE_DEFAULT)
        """Timedelta in seconds after which an external account binding request is considered expired."""

    __c: Config

    def __init__(self, cfg: typing.Union[Config, "acmetk.server.AcmeCA.Config"]):
        super().__init__(cfg=cfg)

        # Use self._extract_mixin_config to extract eab config
        self.__c: AcmeEABMixin.Config = self._extract_mixin_config(cfg, "eab", AcmeEABMixin.Config)
        self.__store: ExternalAccountBindingStore | None = None

    @property
    def _eab_store(self) -> ExternalAccountBindingStore:
        if self.__store is None:
            self.__store = ExternalAccountBindingStore(self._db)
        return self.__store

    async def verify_eab(
        self,
        request: aiohttp.web.Request,
        pub_key: RSAPublicKey | EllipticCurvePublicKey,
        reg: acme.messages.Registration,
    ) -> None:
        """Verifies an ACME Registration request whose payload contains an external account binding JWS.

        :param request: The request
        :param pub_key: The public key that is contained in the outer JWS, i.e. the ACME account key.
        :param reg: The registration message.
        :raises:

            * :class:`acme.messages.Error` if any of the following are true:

                * The request does not contain a valid JWS
                * The request JWS does not contain an *externalAccountBinding* field
                * The EAB JWS was signed with an unsupported algorithm (:attr:`SUPPORTED_EAB_JWS_ALGORITHMS`)
                * The EAB JWS' payload does not contain the same public key as the encapsulating JWS
                * The EAB JWS' signature is invalid
        """
        if not reg.external_account_binding:
            raise acme.messages.Error.with_code("externalAccountRequired", detail=f"Visit {url_for(request, 'eab')}")

        try:
            jws = acme.jws.JWS.from_json(dict(reg.external_account_binding))
        except josepy.errors.DeserializationError:
            raise acme.messages.Error.with_code("malformed", detail="The request does not contain a valid JWS.")

        if jws.signature.combined.alg not in self.SUPPORTED_EAB_JWS_ALGORITHMS:
            raise acme.messages.Error.with_code(
                "badSignatureAlgorithm",
                detail="The external account binding JWS was signed with an unsupported algorithm. "
                f"Supported algorithms: {', '.join([str(alg) for alg in self.SUPPORTED_EAB_JWS_ALGORITHMS])}",
            )

        sig: acme.jws.Header = jws.signature.combined
        kid = sig.kid

        if sig.url != str(forwarded_url(request)):
            raise acme.messages.Error.with_code("unauthorized")

        if isinstance(pub_key, RSAPublicKey):
            pkey_jws = josepy.jwk.JWKRSA.from_json(json.loads(jws.payload))
            pkey = josepy.jwk.JWKRSA(key=pub_key)
        elif isinstance(pub_key, EllipticCurvePublicKey):
            pkey_jws = josepy.jwk.JWKEC.from_json(json.loads(jws.payload))
            pkey = josepy.jwk.JWKEC(key=pub_key)
        else:
            raise TypeError(type(pub_key))

        if pkey_jws != pkey:
            raise acme.messages.Error.with_code(
                "malformed",
                detail="The external account binding does not contain the same public key as the request JWS.",
            )

        if kid is None or not kid:
            raise acme.messages.Error.with_code("malformed", detail="The kid is empty.")

        if kid not in reg.contact + reg.emails:
            if len(reg.contact) == 0:
                # compatibility glue
                object.__setattr__(reg, "contact", (kid,))
            else:
                raise acme.messages.Error.with_code(
                    "malformed", detail="The contact field must contain the email address from the EAB kid"
                )

        if not await self._eab_store.verify(kid, jws):
            raise acme.messages.Error.with_code("unauthorized", detail="The external account binding is invalid.")

    @routes.get("/eab", name="eab")
    @aiohttp_jinja2.template("eab.jinja2")
    async def eab(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        """Handler that displays the user's external account binding credentials, i.e. their *kid* and *hmac_key*
        after their client certificate has been verified and forwarded by the reverse proxy.
        """

        # from unittest.mock import Mock
        # request = Mock(headers={"X-SSL-CERT": urllib.parse.quote(self.data)}, url=request.url)

        if request.headers.get(self.__c.header) is None:
            response = aiohttp_jinja2.render_template("eab.jinja2", request, {})
            response.set_status(403)
            response.text = (
                f"An External Account Binding requires {self.__c.type} authentication in the {self.__c.header} header. "
            )
            return response

        try:
            kid = _email_from_request(request, self.__c.type, self.__c.header)
        except ValueError as e:
            raise aiohttp.web.HTTPBadRequest(text=str(e))

        async with self._db.session() as session:
            cred = await self._eab_store.create(session, kid, "", "")
            return {"kid": cred.kid, "hmac_key": cred.hmac_key}
