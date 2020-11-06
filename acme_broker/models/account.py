import enum
import json

import josepy
from sqlalchemy import Column, Enum, String, types, JSON
from sqlalchemy.orm import relationship

from . import OrderStatus
from .base import Base, Serializer
from ..util import serialize_pubkey, url_for, names_of


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
    orders = relationship(
        "Order", cascade="all, delete", back_populates="account", lazy="joined"
    )

    def orders_url(self, request):
        return url_for(request, "orders", id=str(self.kid))

    def orders_list(self, request):
        return [
            order.url(request)
            for order in self.orders
            if order.status == OrderStatus.PENDING
        ]

    def authorized_identifiers(self):
        identifiers = [
            identifier for order in self.orders for identifier in order.identifiers
        ]

        return set(identifier.value for identifier in identifiers)

    def validate_cert(self, cert):
        authorized_identifiers = self.authorized_identifiers()

        return names_of(cert).issubset(authorized_identifiers)

    def update(self, upd):
        if contact := upd.contact:
            self.contact = json.dumps(contact)

        # the only allowed state transition is VALID -> DEACTIVATED if requested by the client
        if upd.status == AccountStatus.DEACTIVATED:
            self.status = AccountStatus.DEACTIVATED
        elif upd.status:
            raise ValueError(f"Cannot set an account's status to {upd.status}")

    def serialize(self, request=None):
        d = super().serialize(request)
        d["orders"] = self.orders_url(request)
        return d
