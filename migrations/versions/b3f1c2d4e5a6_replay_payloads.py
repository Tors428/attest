"""decision payloads, raw output hash, replay reports

Revision ID: b3f1c2d4e5a6
Revises: 698141e0a22e
Create Date: 2026-10-18 18:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b3f1c2d4e5a6'
down_revision: Union[str, Sequence[str], None] = '698141e0a22e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('decisions', sa.Column('raw_output_hash', sa.LargeBinary(length=32), nullable=True))
    op.create_table('decision_payloads',
    sa.Column('decision_id', sa.UUID(), nullable=False),
    sa.Column('input_text', sa.Text(), nullable=False),
    sa.Column('raw_output_text', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['decision_id'], ['decisions.id'], ),
    sa.PrimaryKeyConstraint('decision_id')
    )
    op.create_table('replay_reports',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('policy_name', sa.String(length=128), nullable=False),
    sa.Column('candidate_version', sa.Integer(), nullable=False),
    sa.Column('from_seq', sa.BigInteger(), nullable=False),
    sa.Column('to_seq', sa.BigInteger(), nullable=False),
    sa.Column('report', sa.JSON(), nullable=False),
    sa.Column('report_sha256', sa.LargeBinary(length=32), nullable=False),
    sa.Column('signature', sa.LargeBinary(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_replay_reports_created_at'), 'replay_reports', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_replay_reports_created_at'), table_name='replay_reports')
    op.drop_table('replay_reports')
    op.drop_table('decision_payloads')
    op.drop_column('decisions', 'raw_output_hash')
