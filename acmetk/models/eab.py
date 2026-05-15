"""EAB credential persistence — pre-minted by admin (Ansible), looked up at registration time."""

import datetime
import secrets

from sqlalchemy import Column, String, DateTime

from .base import Base


class EABCredential(Base):
    """An External Account Binding credential pair (kid + hmac_key).

    Pre-minted by an admin (e.g. Ansible during host provisioning) or by the legacy
    self-service `/eab` endpoint. Persisted to postgres so a broker restart does not
    invalidate outstanding EAB enrolments.
    """

    __tablename__ = "eab_credentials"

    kid = Column(String, primary_key=True)
    """Key identifier — typically the host's contact email (e.g. host@goldenhelix.com)."""

    hmac_key = Column(String, nullable=False)
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
    def mint(cls, kid: str, lifetime: datetime.timedelta) -> "EABCredential":
        """Create a fresh credential with a random HMAC key. Caller must add() + commit()."""
        now = datetime.datetime.now(datetime.timezone.utc)
        return cls(
            kid=kid,
            hmac_key=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + lifetime,
        )

    def expired(self) -> bool:
        return datetime.datetime.now(datetime.timezone.utc) >= self.expires_at
