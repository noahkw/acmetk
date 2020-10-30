import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, String, ForeignKey, LargeBinary
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from . import Identifier, AuthorizationStatus, Authorization, Challenge
from .base import Base, Serializer
from ..util import url_for


class OrderStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class Order(Base, Serializer):
    __tablename__ = "orders"
    __serialize__ = ["status", "expires", "notBefore", "notAfter"]

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    status = Column("status", Enum(OrderStatus), nullable=False)
    expires = Column(DateTime)
    identifiers = relationship("Identifier", cascade="all, delete", lazy="joined")
    notBefore = Column(DateTime)
    notAfter = Column(DateTime)
    account_kid = Column(String, ForeignKey("accounts.kid"), nullable=False)
    account = relationship("Account", back_populates="orders")
    certificate = Column(LargeBinary)

    def finalize_url(self, request):
        return url_for(request, "finalize-order", id=str(self.id))

    def certificate_url(self, request):
        return url_for(request, "certificate", id=str(self.id))

    async def finalize(self):
        if self.status != OrderStatus.PENDING:
            return self.status

        all_valid = True

        for identifier in self.identifiers:
            for authorization in identifier.authorizations:
                if authorization.status != AuthorizationStatus.VALID:
                    all_valid = False
                    break

        self.status = OrderStatus.READY if all_valid else self.status
        return self.status

    def serialize(self, request=None):
        d = Serializer.serialize(self)
        d["identifiers"] = Serializer.serialize_list(self.identifiers)

        authorizations = []
        for identifier in self.identifiers:
            authorizations.extend(
                [
                    authorization.url(request)
                    for authorization in identifier.authorizations
                    if authorization.status == AuthorizationStatus.PENDING
                ]
            )

        d["authorizations"] = authorizations
        d["finalize"] = self.finalize_url(request)

        if self.status == OrderStatus.VALID:
            d["certificate"] = self.certificate_url(request)

        return d

    @classmethod
    def from_obj(cls, account, obj):
        identifiers = [
            Identifier.from_obj(identifier) for identifier in obj.identifiers
        ]
        for identifier in identifiers:
            identifier.authorizations = Authorization.create_all(identifier)

            for authorization in identifier.authorizations:
                authorization.challenges = Challenge.create_all()

        order = Order(
            expires=obj.expires,
            status=obj.status or OrderStatus.PENDING,
            account=account,
            identifiers=identifiers,
        )

        return order
