import enum
import typing
import uuid
from datetime import datetime, timezone, timedelta

import acme.messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import (
    Column,
    Enum,
    DateTime,
    String,
    ForeignKey,
    LargeBinary,
    TypeDecorator,
    Integer,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .authorization import AuthorizationStatus, Authorization
from .base import Serializer, Entity, AcmeErrorType
from .challenge import Challenge
from .identifier import Identifier
from ..util import url_for, names_of


class CSRType(TypeDecorator):
    """x509 Certificate as PEM"""

    impl = LargeBinary

    def process_bind_param(self, value, dialect):
        if value:
            return value.public_bytes(encoding=serialization.Encoding.PEM)
        return value

    def process_result_value(self, value, dialect):
        if value:
            return x509.load_pem_x509_csr(value)
        return value


class OrderStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class Order(Entity, Serializer):
    """Database model for ACME order objects.

    `7.1.3. Order Objects <https://tools.ietf.org/html/rfc8555#section-7.1.3>`_
    """

    __tablename__ = "orders"
    __serialize__ = frozenset(["status", "expires", "notBefore", "notAfter"])
    __diff__ = frozenset(
        ["status", "expires", "notBefore", "notAfter", "proxied_url", "proxied_error"]
    )
    __mapper_args__ = {
        "polymorphic_identity": "order",
    }

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)

    order_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    """The order's ID."""
    proxied_url = Column(String, nullable=True, unique=False)
    """The order's URL at the remote CA."""
    proxied_error = Column(AcmeErrorType, nullable=True)
    """The error that occured at the remote CA while processing the order."""
    status = Column("status", Enum(OrderStatus), nullable=False)
    """The order's status."""
    expires = Column(DateTime(timezone=True), nullable=False)
    """The :class:`datetime.datetime` from which the order is considered expired."""
    identifiers = relationship(
        "Identifier",
        cascade="all, delete",
        lazy="noload",
        foreign_keys="Identifier.order_id",
    )
    """List of identifiers (:class:`~acmetk.models.identifier.Identifier`) associated with the order."""
    notBefore = Column(DateTime(timezone=True))
    """The requested *notBefore* field in the certificate."""
    notAfter = Column(DateTime(timezone=True))
    """The requested *notAfter* field in the certificate."""
    account_id = Column(
        UUID(as_uuid=True), ForeignKey("accounts.account_id"), nullable=False
    )
    account = relationship(
        "Account", back_populates="orders", lazy="noload", foreign_keys=account_id
    )
    """The :class:`~acmetk.models.account.Account` that created the order."""
    certificate = relationship(
        "Certificate",
        uselist=False,
        single_parent=True,
        back_populates="order",
        lazy="noload",
        foreign_keys="Certificate.order_id",
    )
    """The :class:`~acmetk.models.certificate.Certificate` that was generated as a result of the order."""
    csr = Column(CSRType)
    """The :class:`cryptography.x509.CertificateSigningRequest` that was submitted by the client."""

    def url(self, request) -> str:
        """Returns the order's URL.

        :param request: The client request needed to build the URL.
        :return: The order's URL.
        """
        return url_for(request, "orders", id=str(self.order_id))

    def finalize_url(self, request) -> str:
        """Returns the order's *finalize* URL.

        :param request: The client request needed to build the URL.
        :return: The URL at which the client may request the order to be finalized.
        """
        return url_for(request, "finalize-order", id=str(self.order_id))

    def certificate_url(self, request):
        """Returns the order's *certificate* URL.

        :param request: The client request needed to build the URL.
        :return: The URL at which the client may download the certificate that was generated as a result of the order.
        """
        return url_for(request, "certificate", id=str(self.certificate.certificate_id))

    def validate_csr(self, csr: "cryptography.x509.CertificateSigningRequest") -> bool:
        """Validates whether the given CSR's names equal the order's identifiers.

        Accounts for different capitalizations.

        :param cert: The CSR to validate.
        :return: *True* iff the set of names in the CSR equals the order's set of identifiers.
        """
        identifiers = set(identifier.value.lower() for identifier in self.identifiers)

        return identifiers == names_of(csr, lower=True)

    async def validate(self) -> OrderStatus:
        """Validates the order.

        This method is usually not called directly. Rather,
        :func:`acmetk.models.authorization.Authorization.validate` calls it as a authorization that corresponds
        to the order is being validated.

        :param session: The open database session.
        :return: The order's status after validation.
        """
        if self.status != OrderStatus.PENDING:
            return self.status

        if datetime.now(timezone.utc) > self.expires:
            self.status = OrderStatus.INVALID
            return self.status

        for identifier in self.identifiers:
            if identifier.authorization.status == AuthorizationStatus.INVALID:
                self.status = OrderStatus.INVALID
                break
            if not identifier.authorization.is_valid():
                break
        else:
            self.status = OrderStatus.READY

        return self.status

    def serialize(self, request=None) -> dict:
        d = super().serialize(request)
        d["identifiers"] = super().serialize_list(self.identifiers)

        # Section on which authorizations to include:
        # https://tools.ietf.org/html/rfc8555#section-7.1.3
        def show_authz(authorization) -> bool:
            if self.status in (OrderStatus.VALID, OrderStatus.INVALID):
                return authorization.is_valid()
            else:  # self.status in (OrderStatus.PENDING, OrderStatus.PROCESSING, OrderStatus.READY):
                return (
                    authorization.status == AuthorizationStatus.PENDING
                    or authorization.is_valid()
                )

        d["authorizations"] = [
            identifier.authorization.url(request)
            for identifier in self.identifiers
            if show_authz(identifier.authorization)
        ]

        d["finalize"] = self.finalize_url(request)

        if self.status == OrderStatus.VALID:
            d["certificate"] = self.certificate_url(request)

        if self.proxied_error:
            d["error"] = self.proxied_error.to_partial_json()

        return d

    @classmethod
    def from_obj(
        cls,
        account: "acmetk.models.account.Account",
        obj: acme.messages.NewOrder,
        challenge_types: typing.Iterable["acmetk.models.challenge.ChallengeType"],
    ) -> "Order":
        """A factory that constructs a new :class:`Order` from a message object.

        The field *expires* is set to 7 days in the future from the time this method is called and
        the *status* is initially set to *pending*.

        Furthermore, the order object is automatically associated with the given account and all
        :class:`~acmetk.models.identifier.Identifier`, :class:`~acmetk.models.authorization.Authorization`,
        and :class:`~acmetk.models.challenge.Challenge` objects are created as well as associated with the order.

        :param account: The account's key.
        :param obj: The registration message object.
        :param challenge_types: The types of challenges to create.
        :return: The constructed order.
        """
        identifiers = [
            Identifier.from_obj(identifier) for identifier in obj.identifiers
        ]

        for identifier in identifiers:
            identifier.authorization = Authorization.for_identifier(identifier)
            identifier.authorization.challenges = Challenge.create_types(
                challenge_types
            )

        order = Order(
            expires=datetime.now(timezone.utc) + timedelta(days=7),
            status=OrderStatus.PENDING,
            account=account,
            identifiers=identifiers,
        )

        return order

    @property
    def account_of(self):
        return self.account

    @property
    def order_of(self):
        return self
