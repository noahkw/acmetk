"""using JSONB

Revision ID: 24004ca7a5ea
Revises: da620267c2f6
Create Date: 2021-03-04 07:40:24.478687

"""

from alembic import op
import sqlalchemy as sa
import acmetk.models.account
import acmetk.models.base
import acmetk.models.order
import acmetk.models.certificate

import sqlalchemy
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "24004ca7a5ea"
down_revision = "da620267c2f6"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        table_name="changes", column_name="data", nullable=False, type_=postgresql.JSONB
    )
    op.alter_column(
        table_name="challenges",
        column_name="error",
        nullable=True,
        type_=postgresql.JSONB,
    )
    op.alter_column(
        table_name="orders",
        column_name="proxied_error",
        nullable=True,
        type_=postgresql.JSONB,
    )


def downgrade():
    op.alter_column(
        table_name="changes", column_name="data", nullable=False, type_=sqlalchemy.JSON
    )
    op.alter_column(
        table_name="challenges",
        column_name="error",
        nullable=True,
        type_=postgresql.JSON,
    )
    op.alter_column(
        table_name="orders",
        column_name="proxied_error",
        nullable=True,
        type_=postgresql.JSON,
    )
