import datetime
import enum
import typing
import uuid

from sqlalchemy import Column, Enum, DateTime, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

import acmetk.server.challenge_validator
from .base import Serializer, Entity, AcmeErrorType
from ..util import url_for


class ChallengeStatus(str, enum.Enum):
    # subclassing str simplifies json serialization using json.dumps
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class ChallengeType(str, enum.Enum):
    """The types that a :class:`Challenge` can have.

    Subclassing :class:`str` simplifies json serialization using :func:`json.dumps`.
    """

    HTTP_01 = "http-01"
    """The ACME *http-01* challenge type.
    See `8.3. HTTP Challenge <https://tools.ietf.org/html/rfc8555#section-8.3>`_"""
    DNS_01 = "dns-01"
    """The ACME *dns-01* challenge type.
    See `8.4. DNS Challenge <https://tools.ietf.org/html/rfc8555#section-8.4>`_"""
    TLS_ALPN_01 = "tls-alpn-01"
    """The ACME *tls-alpn-01* challenge type.
    See `RFC 8737 <https://tools.ietf.org/html/rfc8737>`_"""


class Challenge(Entity, Serializer):
    """Database model for ACME challenge objects.

    `8. Identifier Validation Challenges <https://tools.ietf.org/html/rfc8555#section-8>`_
    """

    __tablename__ = "challenges"
    __serialize__ = frozenset(["type", "validated", "token", "status"])
    __diff__ = frozenset(["type", "validated", "token", "status", "error"])
    __mapper_args__ = {
        "polymorphic_identity": "challenge",
    }

    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    challenge_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    """The challenge's ID."""
    authorization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("authorizations.authorization_id"),
        nullable=False,
    )
    authorization = relationship(
        "Authorization",
        back_populates="challenges",
        lazy="noload",
        foreign_keys=authorization_id,
    )
    """The :class:`~acmetk.models.authorization.Authorization` associated with the challenge."""
    type = Column("type", Enum(ChallengeType), nullable=False)
    """The challenge's type (:class:`ChallengeType`)."""
    status = Column("status", Enum(ChallengeStatus), nullable=False)
    """The challenge's status."""
    validated = Column(DateTime(timezone=True))
    """The :class:`datetime.datetime` when the challenge was validated."""
    token = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True)
    """The token that is used during the challenge validation process.
    See `8.1.  Key Authorizations <https://tools.ietf.org/html/rfc8555#section-8.1>`_"""
    error = Column(AcmeErrorType, nullable=True)
    """The error that occurred while validating the challenge."""

    def url(self, request) -> str:
        """Returns the challenge's URL.

        :param request: The client request needed to build the URL.
        :return: The challenge's URL.
        """
        return url_for(request, "challenge", id=str(self.challenge_id))

    def serialize(self, request=None) -> dict:
        d = super().serialize(request)
        d["url"] = self.url(request)

        if self.error:
            d["error"] = self.error.to_partial_json()

        return d

    @classmethod
    def create_all(cls) -> typing.List["Challenge"]:
        return cls.create_types(ChallengeType)

    @classmethod
    def create_types(
        cls, types: typing.Iterable[ChallengeType]
    ) -> typing.List["Challenge"]:
        """Returns new pending challenges of the given types.

        :param types: The types of challenges to be created.
        :return: The created challenges.
        """
        return [cls(type=type_, status=ChallengeStatus.PENDING) for type_ in types]

    async def validate(
        self,
        session,
        request,
        validator: "acmetk.server.challenge_validator.ChallengeValidator",
    ) -> ChallengeStatus:
        """Validates the challenge with the given validator.

        Also, it calls its parent authorization's :func:`~acmetk.models.authorization.Authorization.validate`
        method and finally returns the new status after validation.

        :param session: The open database session.
        :param validator: The challenge validator to perform the validation with.
        :return: The challenge's status after validation.
        """
        try:
            await validator.validate_challenge(self, request=request)
        except acmetk.server.challenge_validator.CouldNotValidateChallenge as e:
            self.error = e.to_acme_error()
            self.status = ChallengeStatus.INVALID

        if self.status in (ChallengeStatus.PENDING, ChallengeStatus.PROCESSING):
            self.status = ChallengeStatus.VALID
            self.validated = datetime.datetime.now(datetime.timezone.utc)

        await self.authorization.validate(session)
        return self.status

    @property
    def account_of(self):
        return self.authorization.account_of

    @property
    def order_of(self):
        return self.authorization.order_of
