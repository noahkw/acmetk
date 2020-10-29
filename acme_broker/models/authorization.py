import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base, Serializer
from ..util import url_for


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
    IGNORE = ['id', 'identifier', 'identifier_id', 'challenges']

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    identifier_id = Column(Integer, ForeignKey('identifiers.id'), nullable=False)
    identifier = relationship('Identifier', back_populates='authorizations', lazy='joined')
    status = Column('status', Enum(AuthorizationStatus), nullable=False)
    expires = Column(DateTime)
    wildcard = Column(Boolean, nullable=False)
    challenges = relationship('Challenge', cascade='all, delete', back_populates='authorization', lazy='joined')

    def url(self, request):
        return url_for(request, 'authz', id=str(self.id))

    def __repr__(self):
        return f'<Authorization(id="{self.id}", status="{self.status}", expires="{self.expires}", ' \
               f'identifier="{self.identifier}", order="{self.order}", wildcard="{self.wildcard}, ' \
               f'challenges="{self.challenges}")>'

    def serialize(self, request=None):
        d = Serializer.serialize(self)
        d['challenges'] = Serializer.serialize_list(self.challenges, request=request)
        d['identifier'] = self.identifier.serialize()
        return d

    @classmethod
    def from_identifier(cls, identifier):
        return cls(
            identifier=identifier,
            status=AuthorizationStatus.PENDING,
            wildcard=identifier.value.startswith('*'),
            challenges=[]
        )
