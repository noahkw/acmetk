import enum
import hashlib
import json
import typing
import acme.messages
import josepy
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import Column, Enum, String, types, JSON, Integer, ForeignKey
from sqlalchemy.orm import relationship

from .order import OrderStatus
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
    """Database model for ACME account objects.

    `7.1.2. Account Objects <https://tools.ietf.org/html/rfc8555#section-7.1.2>`_
    """

    __tablename__ = "accounts"
    __serialize__ = __diff__ = frozenset(["status", "contact"])
    __mapper_args__ = {
        "polymorphic_identity": "account",
    }

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    key = Column(JWKType, index=True)
    """The account's public key."""
    kid = Column(String, primary_key=True)
    """The account key's ID."""
    status = Column("status", Enum(AccountStatus))
    """The account's status."""
    contact = Column(JSON)
    """The account's contact info."""
    orders = relationship(
        "Order",
        cascade="all, delete",
        back_populates="account",
        lazy="joined",
        foreign_keys="Order.account_kid",
    )
    """List of orders (:class:`~acme_broker.models.order.Order`) associated with the account."""

    def orders_url(self, request) -> str:
        """Returns the URL of account's orders list.

        :param request: The client request needed to build the URL.
        :return: The URL at which the account's orders list may be requested.
        """
        return url_for(request, "orders", id=str(self.kid))

    def orders_list(self, request) -> typing.List[str]:
        """Returns the account's orders list.

        :param request: The client request needed to build the list of URLs.
        :return: A list of URLs of the account's orders.
        """
        return [
            order.url(request)
            for order in self.orders
            if order.status == OrderStatus.PENDING
        ]

    def authorized_identifiers(self, lower: bool = False) -> typing.Set[str]:
        """Returns the identifiers that the account holds valid authorizations for.

        :param lower: True if the list of authorized identifiers should be lowercased.
        :return: The set of identifiers that the account holds authorizations for.
        """

        # We deliberately don't check whether the identifiers' authorizations have expired,
        # so that older certs may still be revoked.
        # TODO: does this mean that authorizations that were never valid are considered here?
        identifiers = [
            identifier for order in self.orders for identifier in order.identifiers
        ]

        return set(
            identifier.value.lower() if lower else identifier.value
            for identifier in identifiers
        )

    def validate_cert(self, cert: x509.Certificate) -> bool:
        """Validates whether the account holds authorizations for all names present in the certificate.

        :param cert: The certificate to validate.
        :return: *True* iff the account holds authorizations for all names present in the certificate.
        """
        return names_of(cert, lower=True).issubset(
            self.authorized_identifiers(lower=True)
        )

    def update(self, upd):
        """Updates the account with new information.

        Possible updates are currently to the :attr:`contact` field and to the :attr:`status` field.

        :param upd: The requested updates.
        :type upd: :class:`acme_broker.models.messages.AccountUpdate`
        """
        if contact := upd.contact:
            self.contact = json.dumps(contact)

        # the only allowed state transition is VALID -> DEACTIVATED if requested by the client
        if upd.status == AccountStatus.DEACTIVATED:
            self.status = AccountStatus.DEACTIVATED
        elif upd.status:
            raise ValueError(f"Cannot set an account's status to {upd.status}")

    def serialize(self, request=None) -> dict:
        d = super().serialize(request)
        d["orders"] = self.orders_url(request)
        d["contact"] = json.loads(self.contact)
        return d

    @classmethod
    def from_obj(
        cls, jwk: josepy.jwk.JWK, obj: acme.messages.Registration
    ) -> "Account":
        """A factory that constructs a new :class:`Account` from a message object.

        The *kid* is set to the passed JWK's SHA-256 hex digest and the *status* is set to *valid*.

        :param jwk: The account's key.
        :param obj: The registration message object.
        :return: The constructed account.
        """
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
