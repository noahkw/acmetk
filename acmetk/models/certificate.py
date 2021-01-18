import enum
import uuid

import cryptography
from sqlalchemy import (
    Column,
    Enum,
    ForeignKey,
    LargeBinary,
    TypeDecorator,
    Integer,
    Text,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from acmetk.models.messages import RevocationReason
from .base import Serializer, Entity


class x509Certificate(TypeDecorator):
    """x509 Certificate as PEM."""

    impl = LargeBinary

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(self.impl)

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return self._adapt(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return self._convert(value)

    @staticmethod
    def _adapt(cert):
        if isinstance(cert, cryptography.x509.Certificate):
            return cert.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM
            )
        raise TypeError(type(cert))

    @staticmethod
    def _convert(s):
        return cryptography.x509.load_pem_x509_certificate(s)


class CertificateStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    VALID = "valid"
    REVOKED = "revoked"


class Certificate(Entity, Serializer):
    """Database model for certificate objects.

    The ACME RFC does not specify how certificate objects should be structured.
    It merely requires that the resulting certificate chain that the client downloads be encoded
    with the PEM encoding:
    `9.1. Media Type: application/pem-certificate-chain <https://tools.ietf.org/html/rfc8555#section-9.1>`_

    There exists a check constraint on the resulting table to ensure that either the attribute
    :attr:`cert` or the attribute :attr:`full_chain` is set. :attr:`cert` is used by the
    :class:`~acmetk.server.AcmeCA` as it appends its root certificate on certificate download.
    :class:`full_chain` is used by all subclasses of :class:`~acmetk.server.AcmeRelayBase` to easily
    store the full certificate chain that is downloaded from the remote CA.
    """

    __tablename__ = "certificates"
    __mapper_args__ = {
        "polymorphic_identity": "certificate",
    }
    __diff__ = frozenset(["status"])
    __table_args__ = (
        CheckConstraint(
            "cert is not NULL or full_chain is not NULL",
            name="check_cert_or_full_chain",
        ),
    )

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    certificate_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    """The certificate's ID."""
    status = Column("status", Enum(CertificateStatus), nullable=False)
    """The certificate's status."""
    order_id = Column(
        UUID(as_uuid=True),
        ForeignKey("orders.order_id"),
        nullable=False,
        index=True,
        unique=True,
    )
    order = relationship(
        "Order", back_populates="certificate", lazy="noload", foreign_keys=order_id
    )
    """The :class:`acmetk.models.order.Order` associated with the certificate."""
    cert = Column(x509Certificate, nullable=True, index=True)
    """The actual client certificate (:class:`cryptography.x509.Certificate`)."""
    full_chain = Column(Text, nullable=True)
    """The full chain of the certificate (:class:`str`)."""
    reason = Column(Enum(RevocationReason), nullable=True)
    """The revocation reason (:class:`~acmetk.models.messages.RevocationReason`)."""

    def revoke(self, reason: RevocationReason):
        """Sets the certificate's :attr:`status` to *revoked* and copies the given reason.

        :param reason: The reason for revocation.
        """
        self.status = CertificateStatus.REVOKED
        self.reason = reason or RevocationReason.unspecified

    @property
    def account_of(self):
        return self.order.account_of

    @property
    def order_of(self):
        return self.order
