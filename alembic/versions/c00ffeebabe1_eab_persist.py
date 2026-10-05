"""eab credential persistence

Revision ID: c00ffeebabe1
Revises: 3b9114fe9d3a
Create Date: 2026-05-15 04:00:00.000000

Adds the eab_credentials table that replaces the in-memory _pending dict in
ExternalAccountBindingStore. Pre-minted by Ansible via `python -m acmetk eab mint`,
consumed by /new-account when EAB is required.
"""

import sqlalchemy as sa

from alembic import op


revision = "c00ffeebabe1"
down_revision = "3b9114fe9d3a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "externalaccountbindings",
        sa.Column("kid", sa.String(64), nullable=False),
        sa.Column("url", sa.String(128), nullable=False),
        sa.Column("hmac_key", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lifetime", sa.Interval(), nullable=False),
        sa.PrimaryKeyConstraint("kid"),
    )


def downgrade():
    op.drop_table("externalaccountbindings")
