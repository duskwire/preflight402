"""SQLite connection handling and migrations.

Concurrency model: connections are cheap under WAL — open one per
request/task with connect() and pass it to the query functions. Never share
a connection across threads (sqlite3's check_same_thread stays on). WAL
allows one writer and many readers concurrently; writer/writer contention is
absorbed by busy_timeout.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

_DB_DIR = Path(__file__).parent
_MIGRATION_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


def utcnow_iso() -> str:
    """Current UTC time in the canonical timestamp format.

    Millisecond precision with a 'Z' suffix — byte-identical in shape to the
    strftime('%Y-%m-%dT%H:%M:%fZ') defaults in schema.sql, so lexicographic
    comparisons between Python- and SQL-written timestamps stay chronological.
    """
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection in autocommit mode with WAL and foreign keys on."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run the enclosed statements in one BEGIN IMMEDIATE transaction."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def migrate(conn: sqlite3.Connection, *, db_dir: Path | None = None) -> int:
    """Apply pending migrations; return the resulting schema version.

    Version 1 is schema.sql; versions >= 2 come from migrations/NNNN_name.sql
    in db_dir (default: this package's directory). Each migration runs inside
    its own BEGIN IMMEDIATE transaction with user_version updated in the same
    transaction, so a crash mid-migration rolls back cleanly and a rerun picks
    up where it left off. Idempotent: rerunning with nothing pending is a no-op.
    Migrations run with foreign keys disabled (required by the SQLite table-
    rebuild recipe); PRAGMA foreign_key_check guards every COMMIT instead.
    """
    files = _migration_files(db_dir or _DB_DIR)
    target = max(files)
    while True:
        # Foreign keys are disabled around each migration: the SQLite table-
        # rebuild recipe drops and renames parent tables, which with FKs on
        # would fire ON DELETE CASCADE on child rows — and a migration script
        # cannot turn them off itself (PRAGMA foreign_keys is a no-op inside a
        # transaction). foreign_key_check before COMMIT catches any violations
        # a migration would otherwise leave behind unenforced.
        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            # user_version is re-read after taking the write lock so two
            # processes racing to migrate cannot both apply the same migration.
            conn.execute("BEGIN IMMEDIATE")
            try:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                if version >= target:
                    conn.execute("COMMIT")
                    return version
                nxt = version + 1
                for stmt in _statements(files[nxt].read_text()):
                    conn.execute(stmt)
                violations = conn.execute("PRAGMA foreign_key_check").fetchall()
                if violations:
                    tables = sorted({row[0] for row in violations})
                    raise sqlite3.IntegrityError(
                        f"migration {nxt} leaves foreign key violations in: {tables}"
                    )
                # PRAGMA values cannot be bound parameters; nxt is a trusted int.
                conn.execute(f"PRAGMA user_version = {nxt:d}")
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        finally:
            conn.execute("PRAGMA foreign_keys = ON")


def _migration_files(db_dir: Path) -> dict[int, Path]:
    """Map schema version -> migration file, validating contiguity."""
    files = {1: db_dir / "schema.sql"}
    migrations_dir = db_dir / "migrations"
    if migrations_dir.is_dir():
        for path in sorted(migrations_dir.glob("*.sql")):
            match = _MIGRATION_NAME.match(path.name)
            if match is None:
                raise ValueError(f"migration filename not NNNN_name.sql: {path.name}")
            number = int(match.group(1))
            if number < 2:
                raise ValueError(f"migration numbers start at 0002 (schema.sql is 1): {path.name}")
            if number in files:
                raise ValueError(f"duplicate migration number {number}: {path.name}")
            files[number] = path
    numbers = sorted(files)
    if numbers != list(range(1, len(numbers) + 1)):
        raise ValueError(f"non-contiguous migration numbers: {numbers}")
    return files


def _statements(script: str) -> list[str]:
    """Split a SQL script into complete statements, comment- and quote-aware.

    Needed because executescript() cannot run inside an explicit transaction
    (it issues an implicit COMMIT first), which would break migrate()'s
    crash-safety guarantee.
    """
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statements.append(buffer.strip())
            buffer = ""
    tail = "\n".join(
        line for line in buffer.splitlines() if not line.strip().startswith("--")
    ).strip()
    if tail:
        raise ValueError(f"script ends with an unterminated statement: {tail[:80]!r}")
    return statements
