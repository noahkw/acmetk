import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base, Serializer


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

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    authorization_id = Column(UUID(as_uuid=True), ForeignKey('authorizations.id'), nullable=False)
    authorization = relationship('Authorization', back_populates='challenges')
    type = Column('type', Enum(ChallengeType), nullable=False)
    status = Column('status', Enum(ChallengeStatus), nullable=False)
    validated = Column(DateTime)

    def __repr__(self):
        return f'<Challenge(id="{self.id}", status="{self.status}", validated="{self.validated}", ' \
               f'authorization="{self.authorization}", type="{self.type}")>'
