"""init

Revision ID: 5b6b2b8a6b07
Revises:
Create Date: 2021-01-18 08:22:55.752633

"""

from alembic import op
import sqlalchemy as sa
import acmetk.models.account
import acmetk.models.base
import acmetk.models.order
import acmetk.models.certificate
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "5b6b2b8a6b07"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "entities",
        sa.Column("entity", sa.Integer(), nullable=False),
        sa.Column("identity", sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint("entity"),
    )
    op.create_index(op.f("ix_entities_entity"), "entities", ["entity"], unique=False)
    op.create_index(
        op.f("ix_entities_identity"), "entities", ["identity"], unique=False
    )
    op.create_table(
        "accounts",
        sa.Column("_entity", sa.Integer(), nullable=False),
        sa.Column("key", acmetk.models.account.JWKType(), nullable=True),
        sa.Column("kid", sa.String(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("VALID", "DEACTIVATED", "REVOKED", name="accountstatus"),
            nullable=True,
        ),
        sa.Column("contact", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["_entity"],
            ["entities.entity"],
        ),
        sa.PrimaryKeyConstraint("kid"),
    )
    op.create_index(op.f("ix_accounts__entity"), "accounts", ["_entity"], unique=False)
    op.create_index(op.f("ix_accounts_key"), "accounts", ["key"], unique=False)
    op.create_table(
        "changes",
        sa.Column("change", sa.Integer(), nullable=False),
        sa.Column("_entity", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("remote_host", postgresql.INET(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["_entity"],
            ["entities.entity"],
        ),
        sa.PrimaryKeyConstraint("change"),
    )
    op.create_index(op.f("ix_changes__entity"), "changes", ["_entity"], unique=False)
    op.create_index(op.f("ix_changes_change"), "changes", ["change"], unique=False)
    op.create_index(
        op.f("ix_changes_remote_host"), "changes", ["remote_host"], unique=False
    )
    op.create_index(
        op.f("ix_changes_timestamp"), "changes", ["timestamp"], unique=False
    )
    op.create_table(
        "orders",
        sa.Column("_entity", sa.Integer(), nullable=False),
        sa.Column("order_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("proxied_url", sa.String(), nullable=True),
        sa.Column("proxied_error", acmetk.models.base.AcmeErrorType(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING", "READY", "PROCESSING", "VALID", "INVALID", name="orderstatus"
            ),
            nullable=False,
        ),
        sa.Column("expires", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notBefore", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notAfter", sa.DateTime(timezone=True), nullable=True),
        sa.Column("account_kid", sa.String(), nullable=False),
        sa.Column("csr", acmetk.models.order.CSRType(), nullable=True),
        sa.ForeignKeyConstraint(
            ["_entity"],
            ["entities.entity"],
        ),
        sa.ForeignKeyConstraint(
            ["account_kid"],
            ["accounts.kid"],
        ),
        sa.PrimaryKeyConstraint("order_id"),
    )
    op.create_index(op.f("ix_orders__entity"), "orders", ["_entity"], unique=False)
    op.create_table(
        "certificates",
        sa.Column("_entity", sa.Integer(), nullable=False),
        sa.Column("certificate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "status",
            sa.Enum("VALID", "REVOKED", name="certificatestatus"),
            nullable=False,
        ),
        sa.Column("order_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cert", acmetk.models.certificate.x509Certificate(), nullable=True),
        sa.Column("full_chain", sa.Text(), nullable=True),
        sa.Column(
            "reason",
            sa.Enum(
                "unspecified",
                "keyCompromise",
                "cACompromise",
                "affiliationChanged",
                "superseded",
                "cessationOfOperation",
                "certificateHold",
                "removeFromCRL",
                "privilegeWithdrawn",
                "aACompromise",
                name="revocationreason",
            ),
            nullable=True,
        ),
        sa.CheckConstraint(
            "cert is not NULL or full_chain is not NULL",
            name="check_cert_or_full_chain",
        ),
        sa.ForeignKeyConstraint(
            ["_entity"],
            ["entities.entity"],
        ),
        sa.ForeignKeyConstraint(
            ["order_id"],
            ["orders.order_id"],
        ),
        sa.PrimaryKeyConstraint("certificate_id"),
    )
    op.create_index(
        op.f("ix_certificates__entity"), "certificates", ["_entity"], unique=False
    )
    op.create_index(
        op.f("ix_certificates_cert"), "certificates", ["cert"], unique=False
    )
    op.create_index(
        op.f("ix_certificates_order_id"), "certificates", ["order_id"], unique=True
    )
    op.create_table(
        "identifiers",
        sa.Column("_entity", sa.Integer(), nullable=False),
        sa.Column("identifier_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.Enum("DNS", name="identifiertype"), nullable=True),
        sa.Column("value", sa.String(), nullable=True),
        sa.Column("order_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["_entity"],
            ["entities.entity"],
        ),
        sa.ForeignKeyConstraint(
            ["order_id"],
            ["orders.order_id"],
        ),
        sa.PrimaryKeyConstraint("identifier_id"),
    )
    op.create_index(
        op.f("ix_identifiers__entity"), "identifiers", ["_entity"], unique=False
    )
    op.create_table(
        "authorizations",
        sa.Column("_entity", sa.Integer(), nullable=False),
        sa.Column("authorization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identifier_id", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "VALID",
                "INVALID",
                "DEACTIVATED",
                "EXPIRED",
                "REVOKED",
                name="authorizationstatus",
            ),
            nullable=False,
        ),
        sa.Column("expires", sa.DateTime(timezone=True), nullable=True),
        sa.Column("wildcard", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["_entity"],
            ["entities.entity"],
        ),
        sa.ForeignKeyConstraint(
            ["identifier_id"],
            ["identifiers.identifier_id"],
        ),
        sa.PrimaryKeyConstraint("authorization_id"),
    )
    op.create_index(
        op.f("ix_authorizations__entity"), "authorizations", ["_entity"], unique=False
    )
    op.create_index(
        op.f("ix_authorizations_identifier_id"),
        "authorizations",
        ["identifier_id"],
        unique=True,
    )
    op.create_table(
        "challenges",
        sa.Column("_entity", sa.Integer(), nullable=False),
        sa.Column("challenge_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authorization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "type",
            sa.Enum("HTTP_01", "DNS_01", "TLS_ALPN_01", name="challengetype"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING", "PROCESSING", "VALID", "INVALID", name="challengestatus"
            ),
            nullable=False,
        ),
        sa.Column("validated", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("error", acmetk.models.base.AcmeErrorType(), nullable=True),
        sa.ForeignKeyConstraint(
            ["_entity"],
            ["entities.entity"],
        ),
        sa.ForeignKeyConstraint(
            ["authorization_id"],
            ["authorizations.authorization_id"],
        ),
        sa.PrimaryKeyConstraint("challenge_id"),
        sa.UniqueConstraint("token"),
    )
    op.create_index(
        op.f("ix_challenges__entity"), "challenges", ["_entity"], unique=False
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f("ix_challenges__entity"), table_name="challenges")
    op.drop_table("challenges")
    op.drop_index(op.f("ix_authorizations_identifier_id"), table_name="authorizations")
    op.drop_index(op.f("ix_authorizations__entity"), table_name="authorizations")
    op.drop_table("authorizations")
    op.drop_index(op.f("ix_identifiers__entity"), table_name="identifiers")
    op.drop_table("identifiers")
    op.drop_index(op.f("ix_certificates_order_id"), table_name="certificates")
    op.drop_index(op.f("ix_certificates_cert"), table_name="certificates")
    op.drop_index(op.f("ix_certificates__entity"), table_name="certificates")
    op.drop_table("certificates")
    op.drop_index(op.f("ix_orders__entity"), table_name="orders")
    op.drop_table("orders")
    op.drop_index(op.f("ix_changes_timestamp"), table_name="changes")
    op.drop_index(op.f("ix_changes_remote_host"), table_name="changes")
    op.drop_index(op.f("ix_changes_change"), table_name="changes")
    op.drop_index(op.f("ix_changes__entity"), table_name="changes")
    op.drop_table("changes")
    op.drop_index(op.f("ix_accounts_key"), table_name="accounts")
    op.drop_index(op.f("ix_accounts__entity"), table_name="accounts")
    op.drop_table("accounts")
    op.drop_index(op.f("ix_entities_identity"), table_name="entities")
    op.drop_index(op.f("ix_entities_entity"), table_name="entities")
    op.drop_table("entities")
    # ### end Alembic commands ###
