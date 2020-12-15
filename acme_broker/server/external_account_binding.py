import datetime
import json
import secrets
import urllib.parse
import josepy
import acme.jws

from cryptography import x509


class Pending:
    def __init__(
        self,
        rsa_pub_key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey",
        email: str,
        url: str,
    ):
        self.rsa_pub_key = rsa_pub_key
        self.kid = email
        self.url = url
        self.hmac_key = secrets.token_urlsafe(16)
        self.when = datetime.datetime.now()

    def verify(self, signature: str):
        return self.signature == signature

    def expired(self):
        if datetime.datetime.now() - self.when > datetime.timedelta(hours=3):
            return True

        return False

    def _eab(self):
        key_json = json.dumps(
            josepy.jwk.JWKRSA(key=self.rsa_pub_key).to_partial_json()
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
    def signature(self):
        return josepy.b64.b64encode(self._eab().signature.signature).decode()


class ExternalAccountBinding:
    def __init__(self):
        self._pending = dict()

    def create(
        self, request, key: "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey"
    ):
        # the client certificate in the PEM format (urlencoded) for an established SSL connection (1.13.5);
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

        if not (pending := self._pending.get(mail, None)) or pending.exired():
            pending = self._pending[mail] = Pending(key, mail, str(request.url))

        return pending.kid, pending.hmac_key

    def verify(self, kid: str, signature: str):
        if not (pending := self._pending.get(kid.lower(), None)):
            return False

        if pending.expired():
            return False

        return pending.verify(signature)
