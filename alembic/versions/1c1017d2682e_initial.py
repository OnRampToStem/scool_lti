"""initial

Revision ID: 1c1017d2682e
Revises:
Create Date: 2021-06-21 12:07:31.506828

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "1c1017d2682e"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "auth_jwks",
        sa.Column("kid", sa.String(length=64), nullable=False),
        sa.Column("data", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.DateTime(), nullable=False),
        sa.Column("valid_to", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("kid"),
    )
    op.create_table(
        "auth_users",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("client_id", sa.String(length=128), nullable=False),
        sa.Column("client_secret_hash", sa.String(length=128), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_id"),
    )
    op.create_table(
        "cache_objects",
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("ttl", sa.Integer(), nullable=False),
        sa.Column("ttl_type", sa.String(length=10), nullable=False),
        sa.Column("expire_at", sa.DateTime(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "platforms",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=True),
        sa.Column("oidc_auth_url", sa.Text(), nullable=True),
        sa.Column("auth_token_url", sa.Text(), nullable=True),
        sa.Column("jwks_url", sa.Text(), nullable=True),
        sa.Column("client_id", sa.String(length=128), nullable=True),
        sa.Column("client_secret", sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("platforms")
    op.drop_table("cache_objects")
    op.drop_table("auth_users")
    op.drop_table("auth_jwks")
    # ### end Alembic commands ###
