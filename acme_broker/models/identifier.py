import enum

from sqlalchemy import Column, Enum, Integer, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base, Serializer


class IdentifierType(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    DNS = 'dns'


class Identifier(Base, Serializer):
    __tablename__ = 'identifiers'
    IGNORE = ['id', 'order', 'order_id', 'authorizations']

    id = Column(Integer, primary_key=True)
    type = Column('type', Enum(IdentifierType))
    value = Column(String)
    order_id = Column(UUID(as_uuid=True), ForeignKey('orders.id'), nullable=False)
    order = relationship('Order', back_populates='identifiers')
    authorizations = relationship('Authorization', cascade='all, delete', back_populates='identifier', lazy='joined')

    def __repr__(self):
        return f'<Identifier(id="{self.id}", type="{self.type}", value="{self.value}", ' \
               f'order="{self.order}", authorizations="{self.authorizations}")>'

    def serialize(self, request=None):
        d = Serializer.serialize(self)
        # d['authorizations'] = Serializer.serialize_list(self.authorizations)
        return d

    @classmethod
    def from_obj(cls, obj):
        return cls(
            type=IdentifierType(obj.typ.name),
            value=obj.value
        )
