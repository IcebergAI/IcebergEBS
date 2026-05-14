#!/usr/bin/env python3
"""
Migrate marvin_prev.db (single-user schema) to the current multi-user schema.

What this script does:
  1. Adds the user, alertdestination, alertrule, alertlog tables.
  2. Creates an "analyst" user (password supplied via --password or defaults to a
     randomly-generated one printed at the end — change it after migration).
  3. Recreates the extension table with user_id and the new unique constraint,
     preserving all existing rows and their IDs.
  4. fetchlog and installcounthistory rows are preserved unchanged (they reference
     extension.id which does not change).

Usage:
    python migrate_prev.py [--db marvin_prev.db] [--password SECRET]

The script modifies the database IN PLACE. Back it up first if needed.
"""

import argparse
import secrets
import sqlite3
import sys
from datetime import datetime, timezone

import bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def migrate(db_path: str, analyst_password: str) -> None:
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA foreign_keys = OFF")
    con.execute("PRAGMA journal_mode = WAL")

    with con:
        # ── 1. Create new tables ───────────────────────────────────────────
        con.executescript("""
            CREATE TABLE IF NOT EXISTS user (
                id           INTEGER  NOT NULL PRIMARY KEY,
                username     VARCHAR  NOT NULL,
                password_hash VARCHAR NOT NULL,
                email        VARCHAR,
                is_admin     BOOLEAN  NOT NULL DEFAULT 0,
                created_at   DATETIME NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ix_user_username ON user (username);

            CREATE TABLE IF NOT EXISTS alertdestination (
                id         INTEGER  NOT NULL PRIMARY KEY,
                user_id    INTEGER  NOT NULL REFERENCES user(id),
                label      VARCHAR  NOT NULL,
                target     VARCHAR  NOT NULL,
                enabled    BOOLEAN  NOT NULL DEFAULT 1,
                created_at DATETIME NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_alertdestination_user_id
                ON alertdestination (user_id);

            CREATE TABLE IF NOT EXISTS alertrule (
                id             INTEGER  NOT NULL PRIMARY KEY,
                user_id        INTEGER  NOT NULL REFERENCES user(id),
                destination_id INTEGER  NOT NULL REFERENCES alertdestination(id),
                extension_id   INTEGER  REFERENCES extension(id),
                event_type     VARCHAR  NOT NULL,
                enabled        BOOLEAN  NOT NULL DEFAULT 1,
                created_at     DATETIME NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_alertrule_user_id
                ON alertrule (user_id);

            CREATE TABLE IF NOT EXISTS alertlog (
                id           INTEGER  NOT NULL PRIMARY KEY,
                rule_id      INTEGER  NOT NULL REFERENCES alertrule(id),
                extension_id INTEGER  NOT NULL REFERENCES extension(id),
                event_type   VARCHAR  NOT NULL,
                detail       VARCHAR  NOT NULL,
                sent_at      DATETIME NOT NULL,
                success      BOOLEAN  NOT NULL,
                error        VARCHAR
            );
        """)

        # ── 2. Insert analyst user ─────────────────────────────────────────
        now = utcnow()
        password_hash = hash_password(analyst_password)
        con.execute(
            "INSERT INTO user (username, password_hash, email, is_admin, created_at) "
            "VALUES (?, ?, NULL, 0, ?)",
            ("analyst", password_hash, now),
        )
        analyst_id = con.execute(
            "SELECT id FROM user WHERE username = 'analyst'"
        ).fetchone()[0]
        print(f"  Created user 'analyst' with id={analyst_id}")

        # ── 3. Recreate extension table with user_id ───────────────────────
        # SQLite cannot add a NOT NULL column with a default to an existing
        # table (even with a DEFAULT clause when foreign_keys is on). The safe
        # approach is: rename → recreate → copy → drop.

        con.execute("ALTER TABLE extension RENAME TO extension_old")

        con.execute(f"""
            CREATE TABLE extension (
                id               INTEGER  NOT NULL PRIMARY KEY,
                user_id          INTEGER  REFERENCES user(id),
                store            VARCHAR  NOT NULL,
                extension_id     VARCHAR  NOT NULL,
                name             VARCHAR  NOT NULL,
                publisher        VARCHAR  NOT NULL,
                description      VARCHAR,
                version          VARCHAR  NOT NULL,
                install_count    INTEGER,
                last_updated     DATETIME,
                permissions      VARCHAR  NOT NULL,
                store_url        VARCHAR  NOT NULL,
                added_at         DATETIME NOT NULL,
                last_fetched_at  DATETIME,
                watchlist        BOOLEAN  NOT NULL,
                risk_score       INTEGER,
                risk_detail      VARCHAR,
                package_analysis VARCHAR,
                UNIQUE (user_id, store, extension_id)
            )
        """)
        con.execute(
            "CREATE INDEX ix_extension_user_id ON extension (user_id)"
        )

        # Copy all rows, stamping every extension with the analyst user_id.
        con.execute(f"""
            INSERT INTO extension
                (id, user_id, store, extension_id, name, publisher, description,
                 version, install_count, last_updated, permissions, store_url,
                 added_at, last_fetched_at, watchlist, risk_score, risk_detail,
                 package_analysis)
            SELECT
                id, {analyst_id}, store, extension_id, name, publisher, description,
                version, install_count, last_updated, permissions, store_url,
                added_at, last_fetched_at, watchlist, risk_score, risk_detail,
                package_analysis
            FROM extension_old
        """)

        ext_count = con.execute("SELECT COUNT(*) FROM extension").fetchone()[0]
        print(f"  Migrated {ext_count} extensions → user_id={analyst_id}")

        con.execute("DROP TABLE extension_old")

    # fetchlog and installcounthistory reference extension.id which is
    # unchanged, so no work needed there.

    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA integrity_check")

    result = con.execute("PRAGMA integrity_check").fetchone()[0]
    con.close()

    if result != "ok":
        print(f"ERROR: integrity_check returned: {result}", file=sys.stderr)
        sys.exit(1)

    print(f"  integrity_check: {result}")
    print("Migration complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="marvin_prev.db",
                        help="Path to the database to migrate (default: marvin_prev.db)")
    parser.add_argument("--password", default=None,
                        help="Password for the analyst user (default: random, printed below)")
    args = parser.parse_args()

    password = args.password
    generated = False
    if password is None:
        password = secrets.token_urlsafe(16)
        generated = True

    print(f"Migrating: {args.db}")
    if generated:
        print(f"  analyst password (change after login): {password}")

    migrate(args.db, password)

    if generated:
        print(f"\nanalyst password: {password}")
        print("Log in as 'analyst' with the password above and change it immediately.")


if __name__ == "__main__":
    main()
