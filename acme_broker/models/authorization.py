import enum
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import Column, Enum, DateTime, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .challenge import ChallengeStatus
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
    """Database model for ACME authorization objects.

    `7.5. Identifier Authorization <https://tools.ietf.org/html/rfc8555#section-7.5>`_
    """

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
    """The authorization's ID."""
    identifier_id = Column(
        Integer,
        ForeignKey("identifiers.identifier_id"),
        nullable=False,
        unique=True,
        index=True,
    )
    identifier = relationship(
        "Identifier",
        back_populates="authorization",
        lazy="joined",
        foreign_keys=identifier_id,
    )
    """The :class:`~acme_broker.models.identifier.Identifier` associated with the authorization."""
    status = Column("status", Enum(AuthorizationStatus), nullable=False)
    """The authorization's status."""
    expires = Column(DateTime(timezone=True))
    """The :class:`datetime.datetime` from which the authorization is considered expired."""
    wildcard = Column(Boolean, nullable=False)
    """Whether the authorization contains a wildcard."""
    challenges = relationship(
        "Challenge",
        cascade="all, delete",
        back_populates="authorization",
        lazy="joined",
        foreign_keys="Challenge.authorization_id",
    )
    """List of challenges (:class:`~acme_broker.models.challenge.Challenge`) associated with the authorization."""

    def url(self, request) -> str:
        """Returns the authorization's URL.

        :param request: The client request needed to build the URL.
        :return: The authorization's URL.
        """
        return url_for(request, "authz", id=str(self.authorization_id))

    async def validate(self, session) -> AuthorizationStatus:
        """Validates the authorization.

        This method is usually not called directly. Rather, :func:`acme_broker.models.challenge.Challenge.validate`
        calls it as a challenge that corresponds to the authorization is being validated.

        :param session: The open database session.
        :return: The authorization's status after validation.
        """
        if self.is_expired():
            self.status = AuthorizationStatus.EXPIRED
            return self.status

        if self.status != AuthorizationStatus.PENDING:
            return self.status

        statuses = {challenge.status for challenge in self.challenges}

        # check whether at least one challenge is valid/invalid
        if ChallengeStatus.INVALID in statuses:
            self.status = AuthorizationStatus.INVALID
        elif ChallengeStatus.VALID in statuses:
            self.status = AuthorizationStatus.VALID

        await self.identifier.order.validate()
        return self.status

    def is_valid(self) -> bool:
        """Returns whether the authorization is currently valid.

        Takes into account not only the current *status*, but also whether
        the authorization is expired.

        :return: *True* iff the authorization is valid.
        """
        return self.status == AuthorizationStatus.VALID and not self.is_expired()

    def is_expired(self) -> bool:
        """Returns whether the authorization has expired.

        :return: *True* iff the authorization has expired.
        """
        return datetime.now(timezone.utc) > self.expires

    def update(self, upd: "acme_broker.models.messages.AuthorizationUpdate"):
        """Updates the authoziation's status.

        :param upd: The requested status update.
        """

        # the only allowed state transition is VALID -> DEACTIVATED if requested by the client
        if (
            self.status == AuthorizationStatus.VALID
            and upd.status == AuthorizationStatus.DEACTIVATED
        ):
            self.status = AuthorizationStatus.DEACTIVATED
        elif upd.status:
            raise ValueError(f"Cannot set an authorizations's status to {upd.status}")

    def serialize(self, request=None) -> dict:
        d = super().serialize(self)

        # Section on which challenges to include:
        # https://tools.ietf.org/html/rfc8555#section-7.1.4
        def show_chall(challenge) -> bool:
            if self.status == AuthorizationStatus.PENDING:
                return challenge.status in [
                    ChallengeStatus.PENDING,
                    ChallengeStatus.PROCESSING,
                ]
            elif self.status == AuthorizationStatus.VALID:
                return challenge.status == ChallengeStatus.VALID
            elif self.status == AuthorizationStatus.INVALID:
                return challenge.status == ChallengeStatus.INVALID
            else:
                return False

        d["challenges"] = [
            challenge.serialize(request)
            for challenge in self.challenges
            if show_chall(challenge)
        ]

        d["identifier"] = self.identifier.serialize()
        return d

    @classmethod
    def for_identifier(
        cls, identifier: "acme_broker.models.identifier.Identifier"
    ) -> "Authorization":
        """A factory that constructs a new authorization given an
        :class:`~acme_broker.models.identifier.Identifier`.

        The field *expires* is set to 7 days in the future from the time this method is called and
        the *status* is initially set to *pending*.

        The resulting authorization is **not** automatically associated with the given identifier.

        :param identifier: The identifier that the authorization will be associated with.
        :return: The constructed authorization.
        """
        return cls(
            status=AuthorizationStatus.PENDING,
            wildcard=identifier.value.startswith("*"),
            expires=datetime.now(timezone.utc) + timedelta(days=7),
        )

    @property
    def account_of(self):
        return self.identifier.order.account_of

    @property
    def order_of(self):
        return self.identifier.order