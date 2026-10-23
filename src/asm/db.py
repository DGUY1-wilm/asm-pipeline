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

CREATE TABLE IF NOT EXISTS findings (
    ip             TEXT NOT NULL,
    port           TEXT NOT NULL,
    scanner        TEXT NOT NULL,
    check_id       TEXT NOT NULL,
    name           TEXT NOT NULL,
    severity       REAL NOT NULL,
    severity_label TEXT,
    cves           TEXT,
    qod            INTEGER,
    solution       TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    PRIMARY KEY (ip, port, scanner, check_id)
);

CREATE TABLE IF NOT EXISTS kev (
    cve        TEXT PRIMARY KEY,
    vendor     TEXT,
    product    TEXT,
    vuln_name  TEXT,
    date_added TEXT,
    due_date   TEXT,
    ransomware TEXT
);

CREATE TABLE IF NOT EXISTS epss (
    cve        TEXT PRIMARY KEY,
    epss       REAL NOT NULL,
    percentile REAL NOT NULL,
    score_date TEXT
);

CREATE TABLE IF NOT EXISTS finding_scores (
    ip            TEXT NOT NULL,
    port          TEXT NOT NULL,
    scanner       TEXT NOT NULL,
    check_id      TEXT NOT NULL,
    priority      TEXT NOT NULL,
    sort_score    REAL NOT NULL,
    in_kev        INTEGER NOT NULL,
    max_epss      REAL,
    reason        TEXT NOT NULL,
    owner_team    TEXT NOT NULL,
    owner_contact TEXT NOT NULL,
    sla_days      INTEGER NOT NULL,
    due_date      TEXT NOT NULL,
    scored_at     TEXT NOT NULL,
    PRIMARY KEY (ip, port, scanner, check_id)
);

CREATE TABLE IF NOT EXISTS tickets (
    jira_key   TEXT PRIMARY KEY,
    ip         TEXT NOT NULL,
    port       TEXT NOT NULL,
    priority   TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    closed_at  TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    scanner   TEXT NOT NULL,
    ip        TEXT NOT NULL,
    scan_time TEXT NOT NULL,
    PRIMARY KEY (scanner, ip, scan_time)
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