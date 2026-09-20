"""Add watches table for monitoring and drift detection

Revision ID: 006_watches_table
Revises: 005_fingerprints_and_correlations
Create Date: 2026-09-21 00:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "006_watches_table"
down_revision: Union[str, None] = "005_fingerprints_and_correlations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "watches",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, default=True),
        sa.Column("interval_hours", sa.Integer(), nullable=False, default=12),
        sa.Column("last_scan_id", sa.Integer(), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_risk_score", sa.Float(), nullable=True),
        sa.Column("last_risk_level", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_watches_user_id"), "watches", ["user_id"], unique=False)
    op.create_index(op.f("ix_watches_domain"), "watches", ["domain"], unique=False)
    op.create_index(op.f("ix_watches_active"), "watches", ["active"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_watches_active"), table_name="watches")
    op.drop_index(op.f("ix_watches_domain"), table_name="watches")
    op.drop_index(op.f("ix_watches_user_id"), table_name="watches")
    op.drop_table("watches")
