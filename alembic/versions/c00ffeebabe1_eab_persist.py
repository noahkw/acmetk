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
        "eab_credentials",
        sa.Column("kid", sa.String(), nullable=False),
        sa.Column("hmac_key", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("kid"),
    )
    op.create_index(
        op.f("ix_eab_credentials_expires_at"),
        "eab_credentials",
        ["expires_at"],
        unique=False,
    )


def downgrade():
    op.drop_index(op.f("ix_eab_credentials_expires_at"), table_name="eab_credentials")
    op.drop_table("eab_credentials")
