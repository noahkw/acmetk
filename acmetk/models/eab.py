import datetime

import acme.jws
import josepy
import josepy.b64
import josepy.jwa
import josepy.jwk
from sqlalchemy import Column, DateTime, Interval, String

from .base import Base


class ExternalAccountBinding(Base):
    """Represents an external account binding.

    `7.3.4. External Account Binding <https://tools.ietf.org/html/rfc8555#section-7.3.4>`_

    """

    __tablename__ = "externalaccountbindings"

    kid = Column(String(64), primary_key=True)
    """Key identifier — typically the host's contact email (e.g. host@goldenhelix.com)."""

    url = Column(String(128))

    hmac_key = Column(String(64), nullable=False)
    """URL-safe base64 HMAC key shared with the client. Used to sign the EAB JWS at /new-account."""

    created_at = Column(DateTime(timezone=True), nullable=False)
    """When this credential was created."""

    lifetime = Column(Interval(), nullable=False)
    """Lifetime of this credential"""

    def expired(self) -> bool:
        return datetime.datetime.now(datetime.UTC) >= (self.created_at + self.lifetime)

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
