from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

from acme_broker.models import Account
from acme_broker.models.account import AccountStatus
from acme_broker.models.base import Base


class Database:
    def __init__(self, username, password, host, port, db, echo=True, pool_size=5, **kwargs):
        self.engine = create_async_engine(
            f'postgresql+asyncpg://{username}:{password}@{host}:{port}/{db}',
            echo=echo,
            pool_size=pool_size,
            **kwargs
        )

    async def begin(self):
        async with self.engine.begin() as conn:
            # TODO: don't drop_all in prod
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    def session(self):
        return AsyncSession(self.engine)

    async def get_account(self, key):
        async with self.session() as session:
            statement = select(Account).filter(Account.key == key)
            result = (await session.execute(statement)).first()

        return result

    async def add_account(self, account):
        async with self.session() as session:
            session.add(account)
            await session.commit()
