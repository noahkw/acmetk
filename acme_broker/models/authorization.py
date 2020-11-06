import enum
import uuid

from sqlalchemy import Column, Enum, DateTime, ForeignKey, Integer, Boolean, delete
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from . import ChallengeStatus, Challenge
from .base import Serializer, Entity
from ..util import url_for


class AuthorizationStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Authorization(Entity, Serializer):
    __tablename__ = "authorizations"
    __serialize__ = __diff__ = frozenset(["status", "expires", "wildcard"])
    __mapper_args__ = {
        "polymorphic_identity": "authorization",
    }

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    authorization_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    identifier_id = Column(
        Integer, ForeignKey("identifiers.identifier_id"), nullable=False
    )
    identifier = relationship(
        "Identifier",
        back_populates="authorizations",
        lazy="joined",
        foreign_keys=identifier_id,
    )
    status = Column("status", Enum(AuthorizationStatus), nullable=False)
    expires = Column(DateTime(timezone=True))
    wildcard = Column(Boolean, nullable=False)
    challenges = relationship(
        "Challenge",
        cascade="all, delete",
        back_populates="authorization",
        lazy="joined",
        foreign_keys="Challenge.authorization_id",
    )

    def url(self, request):
        return url_for(request, "authz", id=str(self.authorization_id))

    async def finalize(self, session):
        """
        Should only be called by a child challenge as it's done being validated, thus
        checking for a completed challenge here would be redundant.
        """

        # check whether at least one challenge is valid/invalid
        for challenge in self.challenges:
            if challenge.status == ChallengeStatus.VALID:
                self.status = AuthorizationStatus.VALID
                break
            elif challenge.status == ChallengeStatus.INVALID:
                self.status = AuthorizationStatus.INVALID
                break

        # delete all other challenges
        if self.status == AuthorizationStatus.VALID:
            statement = delete(Challenge).filter(
                (Challenge.authorization_id == self.authorization_id)
                & (
                    (Challenge.status == ChallengeStatus.PENDING)
                    | (Challenge.status == ChallengeStatus.PROCESSING)
                )
            )
            await session.execute(statement)

        await self.identifier.order.finalize()

        return self.status

    def update(self, upd):
        # the only allowed state transition is VALID -> DEACTIVATED if requested by the client
        if (
            self.status == AuthorizationStatus.VALID
            and upd.status == AuthorizationStatus.DEACTIVATED
        ):
            self.status = AuthorizationStatus.DEACTIVATED
        elif upd.status:
            raise ValueError(f"Cannot set an authorizations's status to {upd.status}")

    def serialize(self, request=None):
        d = Serializer.serialize(self)
        d["challenges"] = Serializer.serialize_list(self.challenges, request=request)
        d["identifier"] = self.identifier.serialize()
        return d

    @classmethod
    def create_all(cls, identifier):
        return [
            cls(
                status=AuthorizationStatus.PENDING,
                wildcard=identifier.value.startswith("*"),
            )
        ]
