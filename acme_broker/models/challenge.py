import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship

from . import Authorization, AuthorizationStatus
from .base import Base, Serializer
from ..util import url_for


class ChallengeStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    PENDING = 'pending'
    PROCESSING = 'processing'
    VALID = 'valid'
    INVALID = 'invalid'


class ChallengeType(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    HTTP_01 = 'http-01'
    DNS_01 = 'dns-01'


class Challenge(Base, Serializer):
    __tablename__ = 'challenges'
    IGNORE = ['id', 'authorization', 'authorization_id', 'token']

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    authorization_id = Column(UUID(as_uuid=True), ForeignKey('authorizations.id'), nullable=False)
    authorization = relationship('Authorization', back_populates='challenges', lazy='joined')
    type = Column('type', Enum(ChallengeType), nullable=False)
    _status = Column('status', Enum(ChallengeStatus), nullable=False)
    validated = Column(DateTime)
    token = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True)

    @hybrid_property
    def status(self):
        return self._status

    @status.setter
    def status(self, new_status: ChallengeStatus):
        self._status = new_status
        if new_status == ChallengeStatus.VALID:
            self.authorization.status = AuthorizationStatus.VALID

    def url(self, request):
        return url_for(request, 'challenge', id=str(self.id))

    def __repr__(self):
        return f'<Challenge(id="{self.id}", status="{self.status}", validated="{self.validated}", ' \
               f'authorization="{self.authorization}", type="{self.type}", token="{self.token}")>'

    def serialize(self, request=None):
        d = Serializer.serialize(self)
        d['token'] = str(self.token)
        d['url'] = self.url(request)
        return d

    @classmethod
    def from_authorization(cls, authorization: Authorization, type: ChallengeType):
        return cls(
            authorization=authorization,
            type=type,
            status=ChallengeStatus.PENDING
        )

    @classmethod
    def all_challenges_from_authz(cls, authorization: Authorization):
        return [
            cls(authorization=authorization, type=type_, status=ChallengeStatus.PENDING) for type_ in ChallengeType
        ]
