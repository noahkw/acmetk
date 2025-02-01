import enum

import acme.messages
from sqlalchemy import Column, Enum, Integer, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Serializer, Entity


class IdentifierType(str, enum.Enum):
    """The types that a :class:`Identifier` can have.

    `9.7.7. Identifier Types <https://tools.ietf.org/html/rfc8555#section-9.7.7>`_

    https://www.iana.org/assignments/acme/acme.xhtml#acme-identifier-types

    Subclassing :class:`str` simplifies json serialization using :func:`json.dumps`.
    """

    DNS = "dns"
    """
    RFC 8555 - Automatic Certificate Management Environment (ACME)

    https://www.rfc-editor.org/rfc/rfc8555.html#section-9.7.7
    """

    IP = "ip"
    """
    RFC 8738 - Automated Certificate Management Environment (ACME) IP Identifier Validation Extension

    https://www.rfc-editor.org/rfc/rfc8738.html
    """


class Identifier(Entity, Serializer):
    """Database model for ACME identifier objects.

    `8. Identifier Validation Challenges <https://tools.ietf.org/html/rfc8555#section-8>`_
    """

    __tablename__ = "identifiers"
    __serialize__ = __diff__ = frozenset(["type", "value"])
    __mapper_args__ = {
        "polymorphic_identity": "identifier",
    }

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    identifier_id = Column(Integer, primary_key=True)
    """The identifier's ID."""
    type = Column("type", Enum(IdentifierType))
    """The identifier's type (:class:`IdentifierType`)."""
    value = Column(String)
    """The identifier's value. In the case of a *dns* type identifier: the FQDN."""
    order_id = Column(UUID(as_uuid=True), ForeignKey("orders.order_id"), nullable=False)
    order = relationship(
        "Order", back_populates="identifiers", lazy="joined", foreign_keys=order_id
    )
    """The :class:`~acmetk.models.order.Order` associated with the identifier."""
    authorization = relationship(
        "Authorization",
        cascade="all, delete",
        lazy="noload",
        uselist=False,
        single_parent=True,
        foreign_keys="Authorization.identifier_id",
    )
    """The :class:`~acmetk.models.authorization.Authorization` associated with the identifier."""

    @classmethod
    def from_obj(cls, obj: acme.messages.Identifier) -> "Identifier":
        """A factory that constructs a new :class:`Identifier` from a message object.

        :param obj: The identifier message object.
        :return: The constructed identifier.
        """
        return cls(type=IdentifierType(obj.typ.name), value=obj.value)

    @property
    def account_of(self):
        return self.order.account_of

    @property
    def order_of(self):
        return self.order
