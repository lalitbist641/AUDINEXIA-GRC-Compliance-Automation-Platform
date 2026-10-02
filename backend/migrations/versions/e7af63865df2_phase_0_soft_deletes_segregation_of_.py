"""Phase 0: soft deletes, segregation of duties, audit-trail hash chain

* risks / findings / audits / evidence_files gain deleted_at + deleted_by_id:
  the API soft-deletes instead of destroying rows (every normal query filters
  deleted_at IS NULL).
* risks gain risk_acceptance_expires_at and a pending-request block
  (pending_action/reason/expiry/requested_by/requested_at); findings gain the
  same minus the expiry. An owner submits a request and a DIFFERENT manager
  approves it -- see routes/risk_routes.py and routes/audit_routes.py.
* audit_trail_events gain prev_hash + hash (tamper-evident chain, see
  core/audit_trail.py). Nullable: rows written before this migration have none.

All new columns are nullable, so this applies cleanly to a populated database.
Foreign keys are named explicitly -- SQLite's batch mode can't drop an unnamed
constraint, which makes the downgrade impossible otherwise.

Revision ID: e7af63865df2
Revises: a1b2c3d4e501
"""
from alembic import op
import sqlalchemy as sa


revision = 'e7af63865df2'
down_revision = 'a1b2c3d4e501'
branch_labels = None
depends_on = None


def _soft_delete_columns(table):
    with op.batch_alter_table(table, schema=None) as batch_op:
        batch_op.add_column(sa.Column('deleted_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('deleted_by_id', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f(f'ix_{table}_deleted_at'), ['deleted_at'], unique=False)
        batch_op.create_foreign_key(f'fk_{table}_deleted_by_id_users', 'users', ['deleted_by_id'], ['id'])


def _drop_soft_delete_columns(table):
    with op.batch_alter_table(table, schema=None) as batch_op:
        batch_op.drop_constraint(f'fk_{table}_deleted_by_id_users', type_='foreignkey')
        batch_op.drop_index(batch_op.f(f'ix_{table}_deleted_at'))
        batch_op.drop_column('deleted_by_id')
        batch_op.drop_column('deleted_at')


def upgrade():
    for table in ('risks', 'findings', 'audits', 'evidence_files'):
        _soft_delete_columns(table)

    with op.batch_alter_table('risks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('risk_acceptance_expires_at', sa.Date(), nullable=True))
        batch_op.add_column(sa.Column('pending_action', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('pending_reason', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('pending_expiry_date', sa.Date(), nullable=True))
        batch_op.add_column(sa.Column('pending_requested_by_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('pending_requested_at', sa.DateTime(), nullable=True))
        batch_op.create_foreign_key('fk_risks_pending_requested_by_id_users', 'users',
                                    ['pending_requested_by_id'], ['id'])

    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pending_action', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('pending_reason', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('pending_requested_by_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('pending_requested_at', sa.DateTime(), nullable=True))
        batch_op.create_foreign_key('fk_findings_pending_requested_by_id_users', 'users',
                                    ['pending_requested_by_id'], ['id'])

    with op.batch_alter_table('audit_trail_events', schema=None) as batch_op:
        batch_op.add_column(sa.Column('prev_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('hash', sa.String(length=64), nullable=True))


def downgrade():
    with op.batch_alter_table('audit_trail_events', schema=None) as batch_op:
        batch_op.drop_column('hash')
        batch_op.drop_column('prev_hash')

    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_constraint('fk_findings_pending_requested_by_id_users', type_='foreignkey')
        batch_op.drop_column('pending_requested_at')
        batch_op.drop_column('pending_requested_by_id')
        batch_op.drop_column('pending_reason')
        batch_op.drop_column('pending_action')

    with op.batch_alter_table('risks', schema=None) as batch_op:
        batch_op.drop_constraint('fk_risks_pending_requested_by_id_users', type_='foreignkey')
        batch_op.drop_column('pending_requested_at')
        batch_op.drop_column('pending_requested_by_id')
        batch_op.drop_column('pending_expiry_date')
        batch_op.drop_column('pending_reason')
        batch_op.drop_column('pending_action')
        batch_op.drop_column('risk_acceptance_expires_at')

    for table in ('evidence_files', 'audits', 'findings', 'risks'):
        _drop_soft_delete_columns(table)
