import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base, Serializer


class OrderStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    PENDING = 'pending'
    READY = 'ready'
    PROCESSING = 'processing'
    VALID = 'valid'
    INVALID = 'invalid'


class Order(Base, Serializer):
    __tablename__ = 'orders'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    status = Column('status', Enum(OrderStatus), nullable=False)
    expires = Column(DateTime)
    identifiers = relationship('Identifier', cascade='all, delete')
    notBefore = Column(DateTime)
    notAfter = Column(DateTime)
    account_kid = Column(String, ForeignKey('accounts.kid'), nullable=False)
    account = relationship('Account', back_populates='orders')

    def __repr__(self):
        return f'<Order(id="{self.id}", status="{self.status}", expires="{self.expires}", ' \
               f'identifiers="{self.identifiers}", notBefore="{self.notBefore}", notAfter="{self.notAfter}")>'
