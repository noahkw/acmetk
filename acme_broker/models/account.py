import enum

from sqlalchemy import Column, Enum, String, Boolean, types

from .base import Base, Serializer
from ..util import serialize_pubkey, deserialize_pubkey


class AccountStatus(enum.Enum):
    VALID = 'valid'
    DEACTIVATED = 'deactivated'
    REVOKED = 'revoked'


class ComparableRSAKeyType(types.TypeDecorator):
    impl = types.LargeBinary

    def process_bind_param(self, value, dialect):
        return serialize_pubkey(value)

    def process_result_value(self, value, dialect):
        return deserialize_pubkey(value)


class Account(Base, Serializer):
    __tablename__ = 'accounts'

    key = Column(ComparableRSAKeyType, primary_key=True)
    status = Column('status', Enum(AccountStatus))
    contact = Column(String)
    termsOfServiceAgreed = Column(Boolean)

    def __repr__(self):
        return f'<Account(key="{self.key}", status="{self.status}", contact="{self.contact}", ' \
               f'termsOfServiceAgreed="{self.termsOfServiceAgreed}")>'

    def serialize(self):
        d = Serializer.serialize(self)
        del d['key']
        return d
