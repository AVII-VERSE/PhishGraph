"""Add fingerprints and correlations tables

Revision ID: 005_fingerprints_and_correlations
Revises: 004_risk_factors_tables
Create Date: 2026-09-21 00:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "005_fingerprints_and_correlations"
down_revision: Union[str, None] = "004_risk_factors_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "fingerprints",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("ip_set", sa.JSON(), nullable=False),
        sa.Column("asn", sa.String(length=100), nullable=True),
        sa.Column("nameserver_set", sa.JSON(), nullable=False),
        sa.Column("registrar", sa.String(length=255), nullable=True),
        sa.Column("tls_serial", sa.String(length=255), nullable=True),
        sa.Column("tls_issuer", sa.String(length=255), nullable=True),
        sa.Column("favicon_hash", sa.String(length=255), nullable=True),
        sa.Column("page_hash", sa.String(length=255), nullable=True),
        sa.Column("redirect_domain_set", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_fingerprints_scan_id"), "fingerprints", ["scan_id"], unique=False)
    op.create_index(op.f("ix_fingerprints_domain"), "fingerprints", ["domain"], unique=False)
    op.create_index(op.f("ix_fingerprints_asn"), "fingerprints", ["asn"], unique=False)
    op.create_index(op.f("ix_fingerprints_registrar"), "fingerprints", ["registrar"], unique=False)
    op.create_index(op.f("ix_fingerprints_tls_serial"), "fingerprints", ["tls_serial"], unique=False)
    op.create_index(op.f("ix_fingerprints_favicon_hash"), "fingerprints", ["favicon_hash"], unique=False)

    op.create_table(
        "correlations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source_scan_id", sa.Integer(), nullable=False),
        sa.Column("target_scan_id", sa.Integer(), nullable=False),
        sa.Column("correlation_score", sa.Integer(), nullable=False),
        sa.Column("relationship_types", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["source_scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_correlations_source_scan_id"), "correlations", ["source_scan_id"], unique=False)
    op.create_index(op.f("ix_correlations_target_scan_id"), "correlations", ["target_scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_correlations_target_scan_id"), table_name="correlations")
    op.drop_index(op.f("ix_correlations_source_scan_id"), table_name="correlations")
    op.drop_table("correlations")

    op.drop_index(op.f("ix_fingerprints_favicon_hash"), table_name="fingerprints")
    op.drop_index(op.f("ix_fingerprints_tls_serial"), table_name="fingerprints")
    op.drop_index(op.f("ix_fingerprints_registrar"), table_name="fingerprints")
    op.drop_index(op.f("ix_fingerprints_asn"), table_name="fingerprints")
    op.drop_index(op.f("ix_fingerprints_domain"), table_name="fingerprints")
    op.drop_index(op.f("ix_fingerprints_scan_id"), table_name="fingerprints")
    op.drop_table("fingerprints")
