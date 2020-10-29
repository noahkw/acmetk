import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from . import Identifier
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
    IGNORE = ['id', 'account', 'account_kid', 'identifiers']

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
               f'identifiers="{self.identifiers}", notBefore="{self.notBefore}", notAfter="{self.notAfter}", ' \
               f'accounts="{self.account}")>'

    def serialize(self, request=None):
        d = Serializer.serialize(self)
        d['identifiers'] = Serializer.serialize_list(self.identifiers)

        authorizations = []
        for identifier in self.identifiers:
            authorizations.extend([authorization.url(request) for authorization in identifier.authorizations])

        d['authorizations'] = authorizations
        return d

    @classmethod
    def from_obj(cls, account, obj):
        return Order(
            expires=obj.expires,
            identifiers=[Identifier.from_obj(identifier) for identifier in obj.identifiers],
            status=obj.status or OrderStatus.PROCESSING,
            account=account
        )
