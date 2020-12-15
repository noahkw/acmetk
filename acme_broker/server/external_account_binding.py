import datetime
import json
import secrets
import typing
import urllib.parse
import josepy
import acme.jws

from cryptography import x509


class ExternalAccountBinding:
    """Represents an external account binding.

    `7.3.4. External Account Binding <https://tools.ietf.org/html/rfc8555#section-7.3.4>`_
    """

    EXPIRES_AFTER = datetime.timedelta(hours=3)
    """Timedelta after which an external account binding request is considered expired."""

    def __init__(
        self,
        account_pub_key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey",
        email: str,
        url: str,
    ):
        self.account_pub_key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey" = (
            account_pub_key
        )
        """The ACME account key that the external account is to be bound to."""
        self.kid: str = email
        """The key identifier provided by the external binding mechanism."""
        self.url: str = url
        """The *newAccount* URL which is the same as in the encapsulating JWS."""
        self.hmac_key: str = secrets.token_urlsafe(16)
        """The key that is used to symmetrically sign the JWS."""
        self.when: datetime.datetime = datetime.datetime.now()
        """The time when the EAB request was created."""

    def verify(self, signature: str) -> bool:
        """Checks the given signature against the EAB's.

        :param signature: The signature to be verified.
        :return: True iff the given signature and the EAB's are equal.
        """
        return self.signature == signature

    def expired(self) -> bool:
        """Returns whether the EAB has expired.

        :return: True iff the EAB has expired.
        """
        if datetime.datetime.now() - self.when > self.EXPIRES_AFTER:
            return True

        return False

    def _eab(self):
        key_json = json.dumps(
            josepy.jwk.JWKRSA(key=self.account_pub_key).to_partial_json()
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

    @property
    def signature(self) -> str:
        """Returns the EAB's signature."""
        return josepy.b64.b64encode(self._eab().signature.signature).decode()


class ExternalAccountBindingStore:
    """Stores pending :class:`ExternalAccountBinding` requests and offers methods for creation and verification."""

    def __init__(self):
        self._pending = dict()

    def create(
        self, request, key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey"
    ) -> typing.Tuple[str, str]:
        """Creates an :class:`ExternalAccountBinding` request and stores it internally for verification at a later
        point in time.

        :param request: The request that contains the PEM-encoded x509 client certificate in the *X-SSL-CERT* header.
        :param key: The ACME account key that the external account is to be bound to.
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

        if not (pending_eab := self._pending.get(mail, None)) or pending_eab.exired():
            pending_eab = self._pending[mail] = ExternalAccountBinding(
                key, mail, str(request.url)
            )

        return pending_eab.kid, pending_eab.hmac_key

    def verify(self, kid: str, signature: str) -> bool:
        """Verifies an external account binding given its kid and signature.

        :param kid: The EAB's kid.
        :param signature: The EAB's signature.
        :return: True iff verification was successful.
        """
        if not (pending := self._pending.get(kid.lower(), None)):
            return False

        if pending.expired():
            return False

        return pending.verify(signature)
