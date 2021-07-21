"""add bin_data table

Revision ID: 1421571b75af
Revises: 1c1017d2682e
Create Date: 2021-07-22 07:23:55.128809

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1421571b75af'
down_revision = '1c1017d2682e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('bin_data',
    sa.Column('id', sa.String(length=255), nullable=False),
    sa.Column('content_type', sa.String(length=255), nullable=True),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('status', sa.String(length=10), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('data', sa.LargeBinary(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('bin_data')
    # ### end Alembic commands ###
