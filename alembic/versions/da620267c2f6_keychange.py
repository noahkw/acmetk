"""keychange

Revision ID: da620267c2f6
Revises: 5b6b2b8a6b07
Create Date: 2021-01-18 17:03:00.813806

"""

import uuid

from alembic import op
import sqlalchemy as sa
import acmetk.models.account
import acmetk.models.base
import acmetk.models.order
import acmetk.models.certificate
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "da620267c2f6"
down_revision = "5b6b2b8a6b07"
branch_labels = None
depends_on = None

t_account = sa.Table(
    "accounts",
    sa.MetaData(),
    sa.Column("account_id", postgresql.UUID(as_uuid=True)),
    sa.Column("kid"),
)

t_order = sa.Table(
    "orders",
    sa.MetaData(),
    sa.Column("order_id", postgresql.UUID(as_uuid=True)),
    sa.Column("account_kid"),
    sa.Column("account_id"),
)


def upgrade():
    connection = op.get_bind()

    op.add_column("accounts", sa.Column("account_id", postgresql.UUID(as_uuid=True)))
    op.add_column("orders", sa.Column("account_id", postgresql.UUID(as_uuid=True)))

    # update accounts
    result = connection.execute(sa.select(t_account.c.kid)).fetchall()

    for a in result:
        connection.execute(sa.update(t_account).where(t_account.c.kid == a["kid"]).values(account_id=uuid.uuid4()))

    # update orders
    connection.execute(
        sa.update(t_order).where(t_order.c.account_kid == t_account.c.kid).values(account_id=t_account.c.account_id)
    )

    op.alter_column("accounts", "account_id", nullable=False)
    op.alter_column("orders", "account_id", nullable=False)

    op.create_index(op.f("ix_accounts_account_id"), "accounts", ["account_id"], unique=True)
    op.create_index(op.f("ix_accounts_kid"), "accounts", ["kid"], unique=True)

    op.create_foreign_key(None, "orders", "accounts", ["account_id"], ["account_id"])

    op.drop_constraint("orders_account_kid_fkey", "orders", type_="foreignkey")
    op.drop_column("orders", "account_kid")


def downgrade():
    connection = op.get_bind()
    op.add_column(
        "orders",
        sa.Column("account_kid", sa.VARCHAR(), autoincrement=False, nullable=True),
    )

    # update orders
    connection.execute(
        sa.update(t_order).where(t_order.c.account_id == t_account.c.account_id).values(account_kid=t_account.c.kid)
    )

    op.drop_constraint("orders_account_id_fkey", "orders", type_="foreignkey")
    op.create_foreign_key("orders_account_kid_fkey", "orders", "accounts", ["account_kid"], ["kid"])
    op.drop_column("orders", "account_id")
    op.drop_index(op.f("ix_accounts_kid"), table_name="accounts")
    op.drop_index(op.f("ix_accounts_account_id"), table_name="accounts")
    op.drop_column("accounts", "account_id")
