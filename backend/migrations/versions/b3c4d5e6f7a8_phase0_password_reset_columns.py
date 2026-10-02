"""Phase 0: self-service password reset token columns

users gain password_reset_token_hash (SHA-256 of a single-use token -- the raw
token is only ever in the emailed link) and password_reset_expires_at. Both
nullable, so this applies cleanly to a populated database.

Revision ID: b3c4d5e6f7a8
Revises: e7af63865df2
"""
from alembic import op
import sqlalchemy as sa


revision = 'b3c4d5e6f7a8'
down_revision = 'e7af63865df2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password_reset_token_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('password_reset_expires_at', sa.DateTime(), nullable=True))
        batch_op.create_index(batch_op.f('ix_users_password_reset_token_hash'),
                              ['password_reset_token_hash'], unique=False)


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_password_reset_token_hash'))
        batch_op.drop_column('password_reset_expires_at')
        batch_op.drop_column('password_reset_token_hash')
