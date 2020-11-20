import enum
import hashlib
import json

import josepy
from cryptography.hazmat.primitives import serialization
from sqlalchemy import Column, Enum, String, types, JSON, Integer, ForeignKey
from sqlalchemy.orm import relationship

from . import OrderStatus
from .base import Serializer, Entity
from ..util import url_for, names_of


class AccountStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    VALID = "valid"
    DEACTIVATED = "deactivated"
    REVOKED = "revoked"


class JWKType(types.TypeDecorator):
    impl = types.LargeBinary

    def process_bind_param(self, value, dialect):
        return value.key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def process_result_value(self, value, dialect):
        return josepy.jwk.JWK.load(data=value)


class Account(Entity, Serializer):
    __tablename__ = "accounts"
    __serialize__ = __diff__ = frozenset(["status", "contact"])
    __mapper_args__ = {
        "polymorphic_identity": "account",
    }

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    key = Column(JWKType, index=True)
    kid = Column(String, primary_key=True)
    status = Column("status", Enum(AccountStatus))
    contact = Column(JSON)
    orders = relationship(
        "Order",
        cascade="all, delete",
        back_populates="account",
        lazy="joined",
        foreign_keys="Order.account_kid",
    )

    def orders_url(self, request):
        return url_for(request, "orders", id=str(self.kid))

    def orders_list(self, request):
        return [
            order.url(request)
            for order in self.orders
            if order.status == OrderStatus.PENDING
        ]

    def authorized_identifiers(self, lower=False):
        # We deliberately don't check whether the identifiers' authorizations have expired,
        # so that older certs may still be revoked.
        identifiers = [
            identifier for order in self.orders for identifier in order.identifiers
        ]

        return set(
            identifier.value.lower() if lower else identifier.value
            for identifier in identifiers
        )

    def validate_cert(self, cert):
        return names_of(cert, lower=True).issubset(
            self.authorized_identifiers(lower=True)
        )

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
        d["contact"] = json.loads(self.contact)
        return d

    @classmethod
    def from_obj(cls, jwk, obj):
        pem = jwk.key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return Account(
            key=jwk,
            kid=hashlib.sha256(pem).hexdigest(),
            status=AccountStatus.VALID,
            contact=json.dumps(obj.contact),
        )
