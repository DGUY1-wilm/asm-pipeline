"""Database schema and connection helper for the ASM pipeline."""
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    ip          TEXT PRIMARY KEY,
    mac         TEXT,
    vendor      TEXT,
    hostname    TEXT,
    os_name     TEXT,
    os_accuracy INTEGER,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    ip          TEXT NOT NULL REFERENCES assets(ip),
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    state       TEXT NOT NULL,
    name        TEXT,
    product     TEXT,
    version     TEXT,
    extra_info  TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (ip, port, protocol)
);
"""


def connect(db_path="asm.db"):
    """Open the database, enforce foreign keys, and create tables if missing."""
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA foreign_keys = ON")
    con.executescript(SCHEMA)
    return con


if __name__ == "__main__":
    con = connect()
    tables = con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    print(tables)