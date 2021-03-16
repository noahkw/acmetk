import datetime

import acme.messages
import asyncpg
from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
    TypeDecorator,
    MetaData,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import relationship

"alembic - The Importance of Naming Constraints"
meta = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)

Base = declarative_base(metadata=meta)


def __repr__(self):
    attrs = [
        attr
        for attr in inspect(self).attrs.keys()
        if not issubclass(type(getattr(self, attr)), Base)
    ]
    attrs_repr = [f"{attr}={getattr(self, attr)}" for attr in attrs]
    return f"<{type(self).__name__}=({','.join(attrs_repr)})>"


Base.__repr__ = __repr__


class Entity(Base):
    __tablename__ = "entities"

    entity = Column(Integer, primary_key=True, index=True)
    identity = Column(String(50), index=True)
    changes = relationship("Change", backref="entity", lazy="noload")

    __mapper_args__ = {"polymorphic_identity": "entity", "polymorphic_on": identity}


class Change(Base):
    __tablename__ = "changes"

    change = Column(Integer, primary_key=True, index=True)
    _entity = Column(Integer, ForeignKey("entities.entity"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    remote_host = Column(INET, index=True)
    data = Column(JSONB, nullable=False)


class alembic_version(Base):
    __tablename__ = "alembic_version"

    version_num = Column(String(32), nullable=False, primary_key=True)


class AcmeErrorType(TypeDecorator):
    impl = JSONB

    def process_bind_param(self, value, dialect):
        if value:
            return value.json_dumps()
        return value

    def process_result_value(self, value, dialect):
        if value:
            return acme.messages.Error.json_loads(value)
        return value


class Serializer(object):
    __serialize__ = []
    __type_serializers__ = dict()

    def serialize(self, request=None):
        return {
            c: self._serialize_value(getattr(self, c))
            for c in inspect(self).attrs.keys()
            if c in self.__serialize__ and getattr(self, c) is not None
        }

    def _serialize_value(self, value):
        if (type_ := type(value)) in self.__type_serializers__:
            return self.__type_serializers__[type_](value)
        else:
            return value

    @staticmethod
    def serialize_list(list_, request=None):
        return [m.serialize(request=request) for m in list_]

    @staticmethod
    def type_serializer(type_):
        def deco(func):
            Serializer.__type_serializers__[type_] = func

            def wrapped(*args, **kwargs):
                return func(*args, **kwargs)

            return wrapped

        return deco


@Serializer.type_serializer(datetime.datetime)
def serialize_datetime(date_time):
    return date_time.isoformat()


@Serializer.type_serializer(asyncpg.pgproto.pgproto.UUID)
def serialize_uuid(uuid_):
    return str(uuid_)
