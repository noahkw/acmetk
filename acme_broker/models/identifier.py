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

    id = Column(Integer, primary_key=True)
    type = Column('type', Enum(IdentifierType))
    value = Column(String)
    order_id = Column(UUID(as_uuid=True), ForeignKey('orders.id'), nullable=False)
    order = relationship('Order', back_populates='identifiers')
