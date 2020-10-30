from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from acme_broker.models import Account, Identifier, Order, Authorization, Challenge
from acme_broker.models.base import Base


class Database:
    def __init__(self, username, password, host, port, db, pool_size=5, **kwargs):
        self.engine = create_async_engine(
            f'postgresql+asyncpg://{username}:{password}@{host}:{port}/{db}',
            pool_size=pool_size,
            **kwargs
        )

        self.session = sessionmaker(bind=self.engine, class_=AsyncSession)

    async def begin(self):
        async with self.engine.begin() as conn:
            # TODO: don't drop_all in prod
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    async def get_account(self, session, key=None, kid=None):
        statement = select(Account).filter(
            (Account.key == key) | (Account.kid == kid)
        )
        result = (await session.execute(statement)).first()

        return result[0] if result else None

    async def get_authz(self, session, kid, authz_id):
        statement = select(Authorization) \
            .join(Identifier) \
            .join(Order) \
            .join(Account) \
            .filter((kid == Account.kid) & (Authorization.id == authz_id))
        result = (await session.execute(statement)).first()

        return result[0] if result else None

    async def get_challenge(self, session, kid, challenge_id):
        statement = select(Challenge) \
            .join(Authorization) \
            .join(Identifier) \
            .join(Order) \
            .join(Account) \
            .filter((kid == Account.kid) & (Challenge.id == challenge_id))
        result = (await session.execute(statement)).first()

        return result[0] if result else None

    async def get_order(self, session, kid, order_id):
        statement = select(Order) \
            .join(Account) \
            .filter((kid == Account.kid) & (order_id == Order.id))
        result = (await session.execute(statement)).first()

        return result[0] if result else None
