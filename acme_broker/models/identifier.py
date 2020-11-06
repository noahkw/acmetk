import enum

from sqlalchemy import Column, Enum, Integer, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from . import AuthorizationStatus
from .base import Serializer, Entity


class IdentifierType(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    DNS = "dns"


class Identifier(Entity, Serializer):
    __tablename__ = "identifiers"
    __serialize__ = __diff__ = frozenset(["type", "value"])
    __mapper_args__ = {
        "polymorphic_identity": "identifier",
    }

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    identifier_id = Column(Integer, primary_key=True)
    type = Column("type", Enum(IdentifierType))
    value = Column(String)
    order_id = Column(UUID(as_uuid=True), ForeignKey("orders.order_id"), nullable=False)
    order = relationship(
        "Order", back_populates="identifiers", lazy="joined", foreign_keys=order_id
    )
    authorization = relationship(
        "Authorization",
        cascade="all, delete",
        lazy="joined",
        uselist=False,
        single_parent=True,
        foreign_keys="Authorization.identifier_id",
    )

    @classmethod
    def from_obj(cls, obj):
        return cls(type=IdentifierType(obj.typ.name), value=obj.value)

    def is_authorized(self):
        return self.authorization.status == AuthorizationStatus.VALID
