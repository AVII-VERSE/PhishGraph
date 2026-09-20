"""Add dns_records, tls_records, and redirects tables

Revision ID: 002_core_analyzers_tables
Revises: 001_initial_tables
Create Date: 2026-09-20 23:54:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "002_core_analyzers_tables"
down_revision: Union[str, None] = "001_initial_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. dns_records
    op.create_table(
        "dns_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("record_type", sa.String(length=10), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("ttl", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dns_records_scan_id"), "dns_records", ["scan_id"], unique=False)
    op.create_index(op.f("ix_dns_records_record_type"), "dns_records", ["record_type"], unique=False)

    # 2. tls_records
    op.create_table(
        "tls_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=True),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("common_name", sa.String(length=255), nullable=True),
        sa.Column("serial_number", sa.String(length=100), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hostname_valid", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("tls_version", sa.String(length=20), nullable=True),
        sa.Column("certificate_hash", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tls_records_scan_id"), "tls_records", ["scan_id"], unique=False)
    op.create_index(op.f("ix_tls_records_serial_number"), "tls_records", ["serial_number"], unique=False)

    # 3. redirects
    op.create_table(
        "redirects",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("hop_number", sa.Integer(), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("destination_url", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_redirects_scan_id"), "redirects", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_redirects_scan_id"), table_name="redirects")
    op.drop_table("redirects")

    op.drop_index(op.f("ix_tls_records_serial_number"), table_name="tls_records")
    op.drop_index(op.f("ix_tls_records_scan_id"), table_name="tls_records")
    op.drop_table("tls_records")

    op.drop_index(op.f("ix_dns_records_record_type"), table_name="dns_records")
    op.drop_index(op.f("ix_dns_records_scan_id"), table_name="dns_records")
    op.drop_table("dns_records")
