"""Add scan_risk_factors table

Revision ID: 004_risk_factors_tables
Revises: 003_threat_intel_tables
Create Date: 2026-09-21 00:06:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "004_risk_factors_tables"
down_revision: Union[str, None] = "003_threat_intel_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_risk_factors",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("factor_code", sa.String(length=50), nullable=False),
        sa.Column("factor_description", sa.Text(), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("evidence_source", sa.String(length=50), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_risk_factors_scan_id"), "scan_risk_factors", ["scan_id"], unique=False)
    op.create_index(op.f("ix_scan_risk_factors_factor_code"), "scan_risk_factors", ["factor_code"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_risk_factors_factor_code"), table_name="scan_risk_factors")
    op.drop_index(op.f("ix_scan_risk_factors_scan_id"), table_name="scan_risk_factors")
    op.drop_table("scan_risk_factors")
