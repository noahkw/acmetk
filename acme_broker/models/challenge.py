import datetime
import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base, Serializer
from ..util import url_for


class ChallengeStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class ChallengeType(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"


class Challenge(Base, Serializer):
    __tablename__ = "challenges"
    __serialize__ = ["type", "validated", "token"]

    challenge_id = Column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True
    )
    authorization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("authorizations.authorization_id"),
        nullable=False,
    )
    authorization = relationship(
        "Authorization", back_populates="challenges", lazy="joined"
    )
    type = Column("type", Enum(ChallengeType), nullable=False)
    status = Column("status", Enum(ChallengeStatus), nullable=False)
    validated = Column(DateTime(timezone=True))
    token = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True)

    def url(self, request):
        return url_for(request, "challenge", id=str(self.challenge_id))

    def serialize(self, request=None):
        d = Serializer.serialize(self)
        d["url"] = self.url(request)
        return d

    @classmethod
    def create_all(cls):
        return [
            cls(type=type_, status=ChallengeStatus.PENDING) for type_ in ChallengeType
        ]

    async def finalize(self, session):
        """
        Sets the challenge's status and calls its parent authorization's finalize() method.
        """
        self.status = ChallengeStatus.VALID
        self.validated = datetime.datetime.now(datetime.timezone.utc)
        await self.authorization.finalize(session)
        return self.status
