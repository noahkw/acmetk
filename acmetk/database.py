import datetime
import uuid
import typing

import acme
from aiohttp import web
from sqlalchemy import select, event
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, selectinload, aliased

from acmetk import models
from acmetk.models import (
    Account,
    Identifier,
    Order,
    Authorization,
    Challenge,
    Certificate,
)
from acmetk.models.base import Base


class versioned_sessionmaker(sessionmaker):
    def __call__(self, **local_kw) -> AsyncSession:
        """Produce a new :class:`.Session` object using the configuration
        established in this :class:`.sessionmaker`.

        In Python, the ``__call__`` method is invoked on an object when
        it is "called" in the same way as a function::

            Session = sessionmaker()
            session = Session()  # invokes sessionmaker.__call__()

        """
        for k, v in self.kw.items():
            if k == "info" and "info" in local_kw:
                d = v.copy()
                d.update(local_kw["info"])
                local_kw["info"] = d
            else:
                local_kw.setdefault(k, v)

        session = self.class_(**local_kw)
        versioned_session(session)
        return session


def versioned_session(session):
    @event.listens_for(session.sync_session, "before_flush")
    def before_flush(session: AsyncSession, flush_context, instances) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        for obj in session.dirty.union(session.new).union(session.deleted):
            if not hasattr(obj, "__diff__"):
                return
            diff = []

            def change(op, path, value):
                return {"op": op, "path": path, "value": value}

            changed = obj.__diff__ - (
                set(obj._sa_instance_state.unmodified_intersection(obj.__diff__))
                & obj.__diff__
            )

            def value(v):
                if isinstance(v, (str, int, type(None))):
                    return v
                elif isinstance(v, datetime.datetime):
                    return v.isoformat()
                elif isinstance(v, models.Identifier):
                    return v.identifier
                elif isinstance(v, models.Authorization):
                    return v.authorization
                elif isinstance(v, acme.messages.Status):
                    return v.name
                elif isinstance(v, acme.messages.Error):
                    return v.json_dumps()
                else:
                    raise TypeError(type(v))

            for i in changed:
                attr = obj._sa_instance_state.attrs.get(i)
                history = attr.history
                if history.added:
                    if history.deleted:
                        diff.append(change("test", i, value(history.deleted[0])))
                        diff.append(change("replace", i, value(history.added[-1])))
                    else:
                        diff.append(change("add", i, value(history.added[-1])))

            if len(diff) > 0:
                obj.changes.append(
                    models.Change(
                        timestamp=now,
                        remote_host=str(session.info.get("remote_host")),
                        data=diff,
                    )
                )


class Database:
    ALEMBIC_REVISION = "9a65b93bfa0a"

    def __init__(self, connection_string, pool_size=5, **kwargs):
        # asyncpg typeinfo_tree slows down for custom types - including enums when using the pg jit
        # https://github.com/MagicStack/asyncpg/issues/530
        # -> disable the jit via connect_args/server_settings
        # ConnectionDoesNotExistError
        # https://github.com/MagicStack/asyncpg/issues/309
        # -> use pool_pre_ping
        self.engine = create_async_engine(
            connection_string,
            pool_size=pool_size,
            connect_args={"server_settings": {"jit": "off"}},
            # echo=True,
            pool_pre_ping=True,
            native_inet_types=True,
            **kwargs,
        )

        self.session: sessionmaker = versioned_sessionmaker(
            bind=self.engine, class_=AsyncSession
        )

    async def begin(self) -> None:
        """Creates the database's tables according to the models defined in :mod:`acmetk.models`."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with self.session() as session:
            session.add(models.base.alembic_version(version_num=self.ALEMBIC_REVISION))
            await session.flush()
            await session.commit()

    async def drop(self) -> None:
        """Drops all of the database's tables."""
        # FIXME
        # sqlalchemy greenlet_spawn asyncpg resourcewarning
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    async def _recreate(self) -> None:
        """Drops, then recreates all of the database's tables."""
        await self.drop()
        await self.begin()

    @staticmethod
    async def get_account(
        session: AsyncSession, key=None, kid=None, account_id=None
    ) -> typing.Optional[models.Account]:
        statement = (
            select(Account)
            .options(
                selectinload(Account.orders)
                .selectinload(Order.identifiers)
                .selectinload(Identifier.authorization)
            )
            .filter(
                (Account.key == key)
                | (Account.kid == kid)
                | (Account.account_id == account_id)
            )
        )

        result = (await session.execute(statement)).first()

        return result[0] if result else None

    @staticmethod
    async def get_orders_list(
        session: AsyncSession, account_id: uuid.UUID, limit: int, cursor: int = 0
    ) -> list[models.Order]:
        if cursor < 0:
            raise ValueError("Cursor must be >= 0")

        statement = (
            select(Order)
            .filter(Order.account_id == account_id)
            .offset(cursor * limit)
            .limit(
                limit + 1
            )  # read one more row to know whether there are more to be queried later
        )

        result = (await session.execute(statement)).all()

        return [r for (r,) in result]

    @staticmethod
    async def get_authz(
        session: AsyncSession, account_id, authz_id
    ) -> typing.Optional[models.Authorization]:
        order = aliased(Order, flat=True)
        account = aliased(Account, flat=True)
        identifier = aliased(Identifier, flat=True)
        statement = (
            select(Authorization)
            .options(
                selectinload(Authorization.identifier)
                .selectinload(Identifier.order)
                .selectinload(Order.account),
                selectinload(Authorization.challenges),
            )
            .join(identifier, Authorization.identifier_id == identifier.identifier_id)
            .join(order, identifier.order_id == order.order_id)
            .join(account, order.account_id == account.account_id)
            .filter(
                (account_id == account.account_id)
                & (Authorization.authorization_id == authz_id)
            )
        )
        try:
            result = (await session.execute(statement)).first()
        except DBAPIError:
            # authz_id is not a valid UUID
            raise web.HTTPNotFound

        return result[0] if result else None

    @staticmethod
    async def get_challenge(
        session: AsyncSession, account_id, challenge_id
    ) -> typing.Optional[models.Challenge]:
        authorization = aliased(Authorization, flat=True)
        identifier = aliased(Identifier, flat=True)
        order = aliased(Order, flat=True)
        account = aliased(Account, flat=True)

        statement = (
            select(Challenge)
            .options(
                selectinload(Challenge.authorization).options(
                    selectinload(Authorization.challenges),
                    selectinload(Authorization.identifier).options(
                        selectinload(Identifier.order).options(
                            selectinload(Order.account),
                            selectinload(Order.identifiers).selectinload(
                                Identifier.authorization
                            ),
                        ),
                        selectinload(Identifier.authorization),
                    ),
                )
            )
            .join(
                authorization,
                Challenge.authorization_id == authorization.authorization_id,
            )
            .join(identifier, authorization.identifier_id == identifier.identifier_id)
            .join(order, identifier.order_id == order.order_id)
            .join(account, order.account_id == account.account_id)
            .filter(
                (account_id == account.account_id)
                & (Challenge.challenge_id == challenge_id)
            )
        )
        try:
            result = (await session.execute(statement)).first()
        except DBAPIError:
            # challenge_id is not a valid UUID
            raise web.HTTPNotFound

        v = result[0] if result else None
        if v:
            assert v.authorization.identifier.order.account
        return v

    @staticmethod
    async def get_order(
        session: AsyncSession, account_id, order_id
    ) -> typing.Optional[models.Order]:
        account = aliased(Account, flat=True)
        statement = (
            select(Order)
            .options(
                selectinload(Order.account),
                selectinload(Order.identifiers).selectinload(Identifier.authorization),
                selectinload(Order.certificate),
            )
            .join(account, Order.account_id == account.account_id)
            .filter((account_id == account.account_id) & (order_id == Order.order_id))
        )
        try:
            result = (await session.execute(statement)).first()
        except DBAPIError:
            # order_id is not a valid UUID
            raise web.HTTPNotFound

        return result[0] if result else None

    @staticmethod
    async def get_certificate(
        session: AsyncSession, account_id=None, certificate_id=None, certificate=None
    ) -> typing.Optional[models.Certificate]:
        order = aliased(Order, flat=True)
        account = aliased(Account, flat=True)
        if account_id and certificate_id:
            statement = (
                select(Certificate)
                .options(selectinload(Certificate.order).selectinload(Order.account))
                .join(order, Certificate.order_id == order.order_id)
                .join(account, order.account_id == account.account_id)
                .filter(
                    (account_id == account.account_id)
                    & (Certificate.certificate_id == certificate_id)
                )
            )
        elif certificate:
            statement = (
                select(Certificate)
                .filter(Certificate.cert == certificate)
                .options(selectinload(Certificate.order).selectinload(Order.account))
                .join(order, Certificate.order_id == order.order_id)
                .join(account, order.account_id == account.account_id)
            )
        else:
            raise ValueError(
                "Either kid and certificate_id OR certificate should be specified"
            )

        try:
            result = (await session.execute(statement)).first()
        except DBAPIError:
            # certificate_id is not a valid UUID
            raise web.HTTPNotFound

        return result[0] if result else None
