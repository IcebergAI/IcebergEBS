"""oidc sso

Revision ID: b7c8d9e0f1a2
Revises: 876baae8d10b
Create Date: 2026-07-17 15:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = "b7c8d9e0f1a2"
down_revision: Union[str, None] = "876baae8d10b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SSO accounts have no local password (#32); the password login path refuses
    # NULL-hash rows (auth.verify_credentials).
    op.alter_column("user", "password_hash", existing_type=sqlmodel.sql.sqltypes.AutoString(), nullable=True)
    # Backfill-then-drop-default pattern: every pre-SSO row is a local account.
    op.add_column(
        "user",
        sa.Column("auth_provider", sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default="local"),
    )
    op.alter_column("user", "auth_provider", server_default=None)
    op.add_column("user", sa.Column("oidc_issuer", sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column("user", sa.Column("oidc_subject", sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column("user", sa.Column("auth_tenant", sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column(
        "user",
        sa.Column("role_managed_by_idp", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("user", "role_managed_by_idp", server_default=None)
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_user_auth_provider"), ["auth_provider"], unique=False)
        # An OIDC account is keyed on the immutable, validated (issuer, subject) pair
        # (the adapter key is admin-configurable and could be re-pointed at another
        # issuer). Postgres treats NULL as distinct, so local rows never collide.
        batch_op.create_unique_constraint("uq_user_issuer_subject", ["oidc_issuer", "oidc_subject"])
        # Local-xor-subject, and issuer present iff subject present.
        batch_op.create_check_constraint(
            "ck_user_local_xor_subject", "(auth_provider = 'local') = (oidc_subject IS NULL)"
        )
        batch_op.create_check_constraint(
            "ck_user_issuer_subject_together", "(oidc_issuer IS NULL) = (oidc_subject IS NULL)"
        )
    # SSO accounts must not share an email (already lowercased at write time) — closes
    # the concurrent-first-login duplicate-account race at the DB layer. Partial so
    # local accounts (free-form / repeatable / NULL emails) are unaffected.
    op.create_index(
        "uq_user_sso_email",
        "user",
        ["email"],
        unique=True,
        postgresql_where=sa.text("oidc_subject IS NOT NULL"),
    )

    # Admin-editable SSO config singleton (#32) — deliberately NO secret columns:
    # client secrets are env-only (see app/config.py).
    op.create_table(
        "oidcsettings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("auth_mode", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_redirect_base_url", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_entra_enabled", sa.Boolean(), nullable=False),
        sa.Column("oidc_entra_client_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_entra_tenant_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_entra_scopes", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_entra_role_claim", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_entra_role_map", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_authentik_enabled", sa.Boolean(), nullable=False),
        sa.Column("oidc_authentik_client_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_authentik_base_url", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_authentik_app_slug", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_authentik_scopes", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_authentik_role_claim", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_authentik_role_map", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_auth0_enabled", sa.Boolean(), nullable=False),
        sa.Column("oidc_auth0_client_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_auth0_domain", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_auth0_scopes", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_auth0_role_claim", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_auth0_role_map", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_okta_enabled", sa.Boolean(), nullable=False),
        sa.Column("oidc_okta_client_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_okta_domain", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_okta_auth_server", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_okta_scopes", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_okta_role_claim", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("oidc_okta_role_map", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        # Backstops for the auth-mode enum + the oidc-requires-a-provider lockout
        # invariant, so a writer bypassing oidc_settings.update_settings can't
        # persist a config the fail-closed startup validation would reject.
        sa.CheckConstraint("auth_mode IN ('local', 'oidc', 'both')", name="ck_oidcsettings_auth_mode"),
        sa.CheckConstraint(
            "auth_mode <> 'oidc' OR (oidc_entra_enabled OR oidc_authentik_enabled "
            "OR oidc_auth0_enabled OR oidc_okta_enabled)",
            name="ck_oidcsettings_oidc_requires_provider",
        ),
    )


def downgrade() -> None:
    op.drop_table("oidcsettings")
    # SSO users have a NULL password_hash; restoring the NOT NULL constraint below
    # would fail while any exist. Removing SSO is inherently destructive to SSO
    # accounts, so drop them (their history rows SET NULL / CASCADE per the schema).
    op.execute('DELETE FROM "user" WHERE password_hash IS NULL')
    op.drop_index("uq_user_sso_email", table_name="user")
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_constraint("ck_user_issuer_subject_together", type_="check")
        batch_op.drop_constraint("ck_user_local_xor_subject", type_="check")
        batch_op.drop_constraint("uq_user_issuer_subject", type_="unique")
        batch_op.drop_index(batch_op.f("ix_user_auth_provider"))
    op.drop_column("user", "role_managed_by_idp")
    op.drop_column("user", "auth_tenant")
    op.drop_column("user", "oidc_subject")
    op.drop_column("user", "oidc_issuer")
    op.drop_column("user", "auth_provider")
    op.alter_column("user", "password_hash", existing_type=sqlmodel.sql.sqltypes.AutoString(), nullable=False)
