"""flag verdict

Revision ID: c7d2e9a1f3b8
Revises: b3f1c2d4e5a6
Create Date: 2026-10-21 10:20:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = 'c7d2e9a1f3b8'
down_revision: Union[str, Sequence[str], None] = 'b3f1c2d4e5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # postgres won't add an enum value inside a transaction block on older versions
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE verdict ADD VALUE IF NOT EXISTS 'FLAG'")


def downgrade() -> None:
    # postgres can't drop a single enum value. leaving it is harmless
    pass
