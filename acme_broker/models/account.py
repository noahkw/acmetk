import enum

import josepy
from sqlalchemy import Column, Enum, String, types, JSON
from sqlalchemy.orm import relationship

from .base import Base, Serializer
from ..util import serialize_pubkey, deserialize_pubkey


class AccountStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    VALID = 'valid'
    DEACTIVATED = 'deactivated'
    REVOKED = 'revoked'


class ComparableRSAKeyType(types.TypeDecorator):
    impl = types.LargeBinary

    def process_bind_param(self, value, dialect):
        return serialize_pubkey(value)

    def process_result_value(self, value, dialect):
        return josepy.util.ComparableRSAKey(deserialize_pubkey(value))


class Account(Base, Serializer):
    __tablename__ = 'accounts'
    __serialize__ = ['status', 'contact']

    key = Column(ComparableRSAKeyType)
    kid = Column(String, primary_key=True)
    status = Column('status', Enum(AccountStatus))
    contact = Column(JSON)
    orders = relationship('Order', cascade='all, delete', back_populates='account')

    def serialize(self, request=None):
        d = Serializer.serialize(self)
        return d
