import datetime
import json
import typing
import urllib.parse

import acme.jws
import acme.messages
import aiohttp.web
import aiohttp_jinja2
import josepy
import sqlalchemy
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


# Note: this module used to expose an in-memory `ExternalAccountBindingStore` keyed
# off pending dict[mail]. That model lost every outstanding EAB on broker restart
# and offered no path for Ansible to mint EAB credentials server-side. EAB pairs
# now persist in postgres via `EABCredential`. The legacy `/eab` HTTP endpoint is
# preserved as a thin wrapper for the self-service / mTLS flow.


class ExternalAccountBindingStore:
    """Database-backed store for EAB credentials.

    Mints new credential rows on `create()`, looks them up on `verify()`.
    Caller wires in the acmetk `Database` instance so we can open async sessions.
    """

    def __init__(self, db: "acmetk.database.Database"):
        self._db = db

    async def create(
        self,
        kid: str,
        lifetime: datetime.timedelta,
    ) -> tuple[str, str]:
        """Mints (or refreshes) an EAB credential for the given kid.

        If a non-expired credential already exists for this kid, return it as-is.
        Otherwise insert a fresh one. Returns (kid, hmac_key).
        """
        async with self._db.session() as session:
            existing = await session.get(EABCredential, kid)
            if existing is not None and not existing.expired():
                return existing.kid, existing.hmac_key

            if existing is not None:
                # Replace stale credential with a fresh pair
                await session.delete(existing)
                await session.flush()

            cred = EABCredential.mint(kid, lifetime)
            session.add(cred)
            await session.commit()
            return cred.kid, cred.hmac_key

    async def verify(
        self,
        kid: str,
        jws: acme.jws.JWS,
    ) -> bool:
        """Look up the credential by kid, verify the JWS signature, check expiry."""
        async with self._db.session() as session:
            cred = await session.get(EABCredential, kid)
            if cred is None:
                return False
            if cred.expired():
                return False

            key = josepy.jwk.JWKOct(key=josepy.b64.b64decode(cred.hmac_key))
            ok = jws.verify(key)
            if ok and cred.consumed_at is None:
                cred.consumed_at = datetime.datetime.now(datetime.timezone.utc)
                await session.commit()
            return ok


class ExternalAccountBinding:
    """JWS-level helper used by clients building EAB requests. Kept around in
    case downstream code or tests construct one directly; the server-side store is now
    the SQLAlchemy model `EABCredential`."""

    def __init__(
        self,
        email: str,
        url: str,
        lifetime: datetime.timedelta,
        hmac_key: typing.Optional[str] = None,
    ):
        import secrets
        self.kid: str = email
        self.url: str = url
        self.hmac_key: str = hmac_key or secrets.token_urlsafe(32)
        self.when: datetime.datetime = datetime.datetime.now()
        self.lifetime: datetime.timedelta = lifetime

    def verify(self, jws: acme.jws.JWS) -> bool:
        key = josepy.jwk.JWKOct(key=josepy.b64.b64decode(self.hmac_key))
        return jws.verify(key)

    def expired(self) -> bool:
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
        return josepy.b64.b64encode(self._eab(key_json).signature.signature).decode()


def _email_from_request(
    request: aiohttp.web.Request, eab_type: str, header: str
) -> str:
    """Extract the contact email from a self-service `/eab` request, either via a
    plain header or by parsing an x509 client cert (mTLS flow). Raises ValueError if
    we cannot determine a unique email."""
    value = request.headers.get(header)
    if value is None:
        raise ValueError(f"{header} header missing")

    if eab_type == "plain":
        return value

    if eab_type == "x509":
        cert = x509.load_pem_x509_certificate(urllib.parse.unquote(value).encode())
        mails: set[str] = set()
        nl = cert.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)
        if nl:
            mails |= set(a.value for a in nl)
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san: x509.SubjectAlternativeName = ext.value
            mails |= set(san.get_values_for_type(x509.RFC822Name))
        except x509.ExtensionNotFound:
            pass

        if len(mails) != 1:
            raise ValueError(f"{len(mails)} mail addresses in cert, expecting 1 ({mails})")
        return mails.pop()

    raise ValueError(f"unknown eab type: {eab_type!r}")


class AcmeEABMixin:
    """Mixin for an AcmeServerBase that wires up EAB credential persistence + the
    legacy self-service `/eab` endpoint.

    EAB pairs are now persisted in postgres (`eab_credentials` table). For
    Ansible-driven enrolment, mint credentials out-of-band via the CLI:

        docker exec acmetk-app python -m acmetk eab mint <connection-string> --email <kid>

    The `/eab` HTTP endpoint is preserved for the self-service / mTLS flow but is
    no longer the only path — and credentials minted via either path survive a
    broker restart.
    """

    SUPPORTED_EAB_JWS_ALGORITHMS: tuple[type]

    EXPIRE_DEFAULT = datetime.timedelta(hours=3)

    class Config(BaseSettings, extra="forbid"):
        required: bool = False
        type: typing.Literal["x509", "plain"] = "plain"
        header: str = "x-auth-request-email"
        expires_after: datetime.timedelta = Field(default_factory=lambda: AcmeEABMixin.EXPIRE_DEFAULT)

    __c: Config

    def __init__(self, cfg):
        super().__init__(cfg=cfg)
        self.__c: AcmeEABMixin.Config = self._extract_mixin_config(cfg, "eab", AcmeEABMixin.Config)
        # self._db is initialised by AcmeServerBase.__init__ AFTER super().__init__()
        # returns, so we defer store construction to first use.
        self.__store: typing.Optional[ExternalAccountBindingStore] = None

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
        """Verifies an ACME Registration request whose payload contains an EAB JWS."""
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

        # Normalize acme contact entries: clients send mailto:user@host URIs in
        # reg.contact per RFC 8555 7.3, but our EAB kid is the bare email address.
        def _norm(c: str) -> str:
            return c[len("mailto:"):] if c.startswith("mailto:") else c

        normalized_contact = tuple(_norm(c) for c in reg.contact + reg.emails)
        if kid not in normalized_contact:
            if len(reg.contact) == 0:
                object.__setattr__(reg, "contact", (f"mailto:{kid}",))
            else:
                raise acme.messages.Error.with_code(
                    "malformed",
                    detail=f"The contact field must contain the email address from the EAB kid ({kid}); got {list(reg.contact)}",
                )

        if not await self._eab_store.verify(kid, jws):
            raise acme.messages.Error.with_code("unauthorized", detail="The external account binding is invalid.")

    @routes.get("/eab", name="eab")
    @aiohttp_jinja2.template("eab.jinja2")
    async def eab(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        """Self-service EAB issuance via mTLS / plain-header flow. Identity proven by
        the reverse-proxy-validated client cert (or by a trusted upstream header)."""
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

        kid_out, hmac_key = await self._eab_store.create(kid, self.__c.expires_after)
        return {"kid": kid_out, "hmac_key": hmac_key}
