"""EAB credential persistence — pre-minted by admin (Ansible), looked up at registration time."""

import datetime
import secrets

import acme.jws
import josepy
import josepy.b64
import josepy.jwk
import josepy.jwa
from sqlalchemy import Column, String, DateTime

from .base import Base


class EABCredential(Base):
    """Represents an external account binding.

    `7.3.4. External Account Binding <https://tools.ietf.org/html/rfc8555#section-7.3.4>`_

    Can be pre-minted by an admin (e.g. Ansible during host provisioning) or by the
    self-service `/eab` endpoint. Persisted to postgres so a broker restart does not
    invalidate outstanding EAB enrolments.
    """

    __tablename__ = "eab_credentials"

    kid = Column(String(64), primary_key=True)
    """Key identifier — typically the host's contact email (e.g. host@goldenhelix.com)."""

    url = Column(String(128))

    hmac_key = Column(String(64), nullable=False)
    """URL-safe base64 HMAC key shared with the client. Used to sign the EAB JWS at /new-account."""

    created_at = Column(DateTime(timezone=True), nullable=False)
    """When this credential was minted."""

    expires_at = Column(DateTime(timezone=True), nullable=False)
    """When this credential expires. After this point, /new-account will reject the EAB."""

    consumed_at = Column(DateTime(timezone=True), nullable=True)
    """Set when the credential has been used by a successful /new-account registration.
    Currently informational only — the broker does not reject re-use, since acme.sh and
    some other clients re-register the same account on each renewal in some configurations."""

    @classmethod
    def create(cls, kid: str, url: str, lifetime: datetime.timedelta) -> "EABCredential":
        """Create a fresh credential with a random HMAC key. Caller must add() + commit().
        :param url:
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        return cls(
            kid=kid,
            url=url,
            hmac_key=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + lifetime,
        )

    def expired(self) -> bool:
        return datetime.datetime.now(datetime.timezone.utc) >= self.expires_at

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

    def verify(
        self,
        jws: acme.jws.JWS,
    ) -> bool:
        """Checks the given signature against the EAB's.

        :param jws: The EAB request JWS to be verified.
        :return: True iff the given signature and the EAB's are equal.
        """
        key = josepy.jwk.JWKOct(key=josepy.b64.b64decode(self.hmac_key))
        return jws.verify(key)
