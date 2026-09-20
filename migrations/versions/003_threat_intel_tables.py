"""Add threat_intel_results table

Revision ID: 003_threat_intel_tables
Revises: 002_core_analyzers_tables
Create Date: 2026-09-20 23:58:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "003_threat_intel_tables"
down_revision: Union[str, None] = "002_core_analyzers_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_results",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("provider_status", sa.String(length=50), nullable=False),
        sa.Column("malicious", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("suspicious", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("provider_score", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("labels", sa.Text(), nullable=True),
        sa.Column("reference_id", sa.String(length=255), nullable=True),
        sa.Column("raw_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_threat_intel_results_scan_id"), "threat_intel_results", ["scan_id"], unique=False)
    op.create_index(op.f("ix_threat_intel_results_provider"), "threat_intel_results", ["provider"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_threat_intel_results_provider"), table_name="threat_intel_results")
    op.drop_index(op.f("ix_threat_intel_results_scan_id"), table_name="threat_intel_results")
    op.drop_table("threat_intel_results")
