import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base, Serializer


class AuthorizationStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    PENDING = 'pending'
    VALID = 'valid'
    INVALID = 'invalid'
    DEACTIVATED = 'deactivated'
    EXPIRED = 'expired'
    REVOKED = 'revoked'


class Authorization(Base, Serializer):
    __tablename__ = 'authorizations'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    identifier_id = Column(Integer, ForeignKey('identifiers.id'), nullable=False)
    identifier = relationship('Identifier', back_populates='authorizations')
    status = Column('status', Enum(AuthorizationStatus), nullable=False)
    expires = Column(DateTime)
    wildcard = Column(Boolean, nullable=False)
    challenges = relationship('Challenge', cascade='all, delete', back_populates='authorization')

    def __repr__(self):
        return f'<Authorization(id="{self.id}", status="{self.status}", expires="{self.expires}", ' \
               f'identifier="{self.identifier}", order="{self.order}", wildcard="{self.wildcard}, ' \
               f'challenges="{self.challenges}")>'
