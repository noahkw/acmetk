import enum
import json

import josepy
from sqlalchemy import Column, Enum, String, types, JSON
from sqlalchemy.orm import relationship

from .base import Base, Serializer
from ..util import serialize_pubkey


class AccountStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    VALID = "valid"
    DEACTIVATED = "deactivated"
    REVOKED = "revoked"


class JWKType(types.TypeDecorator):
    impl = types.LargeBinary

    def process_bind_param(self, value, dialect):
        return serialize_pubkey(value)

    def process_result_value(self, value, dialect):
        return josepy.jwk.JWK.load(data=value)


class Account(Base, Serializer):
    __tablename__ = "accounts"
    __serialize__ = ["status", "contact"]

    key = Column(JWKType, index=True)
    kid = Column(String, primary_key=True)
    status = Column("status", Enum(AccountStatus))
    contact = Column(JSON)
    orders = relationship("Order", cascade="all, delete", back_populates="account")

    def update(self, upd):
        if contact := upd.contact:
            self.contact = json.dumps(contact)

        # the only allowed state transition is VALID -> DEACTIVATED if requested by the client
        if upd.status == "deactivated":
            self.status = AccountStatus.DEACTIVATED
