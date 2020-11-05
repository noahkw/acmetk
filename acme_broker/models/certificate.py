import enum
import uuid

import cryptography
from sqlalchemy import Column, Enum, ForeignKey, LargeBinary, TypeDecorator, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Serializer, Entity


class x509Certifcate(TypeDecorator):
    """x509 Certificate as PEM"""

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
    __tablename__ = "certificates"
    __mapper_args__ = {
        "polymorphic_identity": "certificate",
    }
    __diff__ = frozenset(["status"])

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    certificate_id = Column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True
    )
    status = Column("status", Enum(CertificateStatus), nullable=False)
    order_id = Column(
        UUID(as_uuid=True), ForeignKey("orders.order_id"), nullable=False, index=True
    )
    order = relationship("Order", back_populates="certificate", foreign_keys=order_id)
    cert = Column(x509Certifcate, nullable=False, index=True)
