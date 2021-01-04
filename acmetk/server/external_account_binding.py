import datetime
import json
import secrets
import typing
import urllib.parse

import acme.jws
import acme.messages
import aiohttp_jinja2
import josepy
from cryptography import x509

from acmetk.server.routes import routes
from acmetk.util import url_for, forwarded_url


class ExternalAccountBinding:
    """Represents an external account binding.

    `7.3.4. External Account Binding <https://tools.ietf.org/html/rfc8555#section-7.3.4>`_
    """

    EXPIRES_AFTER = datetime.timedelta(hours=3)
    """Timedelta after which an external account binding request is considered expired."""

    def __init__(
        self,
        email: str,
        url: str,
    ):
        self.kid: str = email
        """The key identifier provided by the external binding mechanism."""
        self.url: str = url
        """The *newAccount* URL which is the same as in the encapsulating JWS."""
        self.hmac_key: str = secrets.token_urlsafe(16)
        """The key that is used to symmetrically sign the JWS."""
        self.when: datetime.datetime = datetime.datetime.now()
        """The time when the EAB request was created."""

    def verify(
        self,
        account_pub_key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey",
        signature: str,
    ) -> bool:
        """Checks the given signature against the EAB's.

        :param account_pub_key: The ACME account key that the external account is to be bound to.
        :param signature: The signature to be verified.
        :return: True iff the given signature and the EAB's are equal.
        """
        return self.signature(account_pub_key) == signature

    def expired(self) -> bool:
        """Returns whether the EAB has expired.

        :return: True iff the EAB has expired.
        """
        if datetime.datetime.now() - self.when > self.EXPIRES_AFTER:
            return True

        return False

    def _eab(self, account_pub_key):
        key_json = json.dumps(
            josepy.jwk.JWKRSA(key=account_pub_key).to_partial_json()
        ).encode()
        decoded_hmac_key = josepy.b64.b64decode(self.hmac_key)
        eab = acme.jws.JWS.sign(
            key_json,
            josepy.jwk.JWKOct(key=decoded_hmac_key),
            josepy.jwa.HS256,
            None,
            self.url,
            self.kid,
        )

        return eab

    def signature(
        self,
        account_pub_key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey",
    ) -> str:
        """Returns the EAB's signature.

        :param account_pub_key: The ACME account key that the external account is to be bound to.
        """
        return josepy.b64.b64encode(
            self._eab(account_pub_key).signature.signature
        ).decode()


class ExternalAccountBindingStore:
    """Stores pending :class:`ExternalAccountBinding` requests and offers methods for creation and verification."""

    def __init__(self):
        self._pending = dict()

    def create(self, request) -> typing.Tuple[str, str]:
        """Creates an :class:`ExternalAccountBinding` request and stores it internally for verification at a later
        point in time.

        :param request: The request that contains the PEM-encoded x509 client certificate in the *X-SSL-CERT* header.
        :return: The resulting pending EAB's :attr:`~ExternalAccountBinding.kid` and
            :attr:`~ExternalAccountBinding.hmac_key`.
        """

        # The client certificate in the PEM format (urlencoded) for an established SSL connection (1.13.5);
        cert = x509.load_pem_x509_certificate(
            urllib.parse.unquote(request.headers["X-SSL-CERT"]).encode()
        )

        if not (
            mail := cert.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)
        ):
            ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            mails = ext.value.get_values_for_type(x509.RFC822Name)

            if len(mails) != 1:
                raise ValueError(f"{len(mails)} mail addresses in cert, expecting 1")

            mail = mails.pop()

        mail = mail.lower()

        if not (pending_eab := self._pending.get(mail, None)) or pending_eab.expired():
            pending_eab = self._pending[mail] = ExternalAccountBinding(
                mail, url_for(request, "new-account")
            )

        return pending_eab.kid, pending_eab.hmac_key

    def verify(
        self,
        account_pub_key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey",
        kid: str,
        signature: str,
    ) -> bool:
        """Verifies an external account binding given its ACME account key, kid and signature.

        :param account_pub_key: The ACME account key that the external account is to be bound to.
        :param kid: The EAB's kid.
        :param signature: The EAB's signature.
        :return: True iff verification was successful.
        """
        if not (pending := self._pending.get(kid.lower(), None)):
            return False

        if pending.expired():
            return False

        return pending.verify(account_pub_key, signature)


class AcmeEAB:
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

    def __init__(self):
        super().__init__()
        self._eab_store = ExternalAccountBindingStore()

    def verify_eab(
        self,
        request,
        pub_key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey",
        reg: acme.messages.Registration,
    ):
        """Verifies an ACME Registration request whose payload contains an external account binding JWS.

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
            raise acme.messages.Error.with_code(
                "externalAccountRequired", detail=f"Visit {url_for(request, 'eab')}"
            )

        try:
            jws = acme.jws.JWS.from_json(dict(reg.external_account_binding))
        except josepy.errors.DeserializationError:
            raise acme.messages.Error.with_code(
                "malformed", detail="The request does not contain a valid JWS."
            )

        if jws.signature.combined.alg not in self.SUPPORTED_EAB_JWS_ALGORITHMS:
            raise acme.messages.Error.with_code(
                "badSignatureAlgorithm",
                detail="The external account binding JWS was signed with an unsupported algorithm. "
                f"Supported algorithms: {', '.join([str(alg) for alg in self.SUPPORTED_EAB_JWS_ALGORITHMS])}",
            )

        sig = jws.signature.combined
        kid = sig.kid
        signature = josepy.b64.b64encode(jws.signature.signature).decode()
        payload_key = josepy.jwk.JWKRSA.from_json(json.loads(jws.payload))

        if sig.url != str(forwarded_url(request)):
            raise acme.messages.Error.with_code("unauthorized")

        if payload_key != josepy.jwk.JWKRSA(key=pub_key):
            raise acme.messages.Error.with_code(
                "malformed",
                detail="The external account binding does not contain the same public key as the request JWS.",
            )

        if kid not in reg.contact + reg.emails:
            raise acme.messages.Error.with_code(
                "malformed",
                detail="The contact field must contain the email address from the "
                "SSL client certificate which was used to request the EAB.",
            )

        if not self._eab_store.verify(pub_key, kid, signature):
            raise acme.messages.Error.with_code(
                "unauthorized", detail="The external account binding is invalid."
            )

    @routes.get("/eab", name="eab")
    @aiohttp_jinja2.template("eab.jinja2")
    async def eab(self, request):
        """Handler that displays the user's external account binding credentials, i.e. their *kid* and *hmac_key*
        after their client certificate has been verified and forwarded by the reverse proxy.
        """

        # from unittest.mock import Mock
        # request = Mock(headers={"X-SSL-CERT": urllib.parse.quote(self.data)}, url=request.url)

        if not request.headers.get("X-SSL-CERT"):
            response = aiohttp_jinja2.render_template("eab.jinja2", request, {})
            response.set_status(403)
            response.text = (
                "An External Account Binding may only be created if a valid client certificate "
                "is sent with the request."
            )
            return response

        kid, hmac_key = self._eab_store.create(request)
        return {"kid": kid, "hmac_key": hmac_key}
