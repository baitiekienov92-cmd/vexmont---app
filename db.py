"""Тонкий слой БД: PostgreSQL на Render (DATABASE_URL), SQLite локально."""
import os
import sqlite3

from flask import g

URL = os.environ.get("DATABASE_URL", "sqlite:///prorab.db")
PG = URL.startswith("postgres")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id {PK}, name TEXT NOT NULL, phone TEXT UNIQUE NOT NULL, pw TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'prorab', status TEXT NOT NULL DEFAULT 'pending',
  company TEXT DEFAULT '', notes_seen TEXT DEFAULT '', created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS complexes(
  id {PK}, name TEXT NOT NULL, sub TEXT DEFAULT '', city TEXT DEFAULT 'Алматы', created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS access(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  complex_id INTEGER NOT NULL REFERENCES complexes(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, complex_id));
CREATE TABLE IF NOT EXISTS flats(
  id {PK}, complex_id INTEGER NOT NULL REFERENCES complexes(id) ON DELETE CASCADE,
  number TEXT NOT NULL, kind TEXT DEFAULT 'типовой');
CREATE TABLE IF NOT EXISTS works(
  id {PK}, flat_id INTEGER NOT NULL REFERENCES flats(id) ON DELETE CASCADE,
  stage INTEGER NOT NULL, idx INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'no',
  date TEXT DEFAULT '', ret TEXT DEFAULT '', sent_by INTEGER);
CREATE TABLE IF NOT EXISTS photos(
  id {PK}, work_id INTEGER NOT NULL REFERENCES works(id) ON DELETE CASCADE,
  data {BLOB} NOT NULL, mime TEXT NOT NULL, user_id INTEGER, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  id {PK}, flat_id INTEGER NOT NULL REFERENCES flats(id) ON DELETE CASCADE,
  stage INTEGER, kind TEXT NOT NULL, text TEXT NOT NULL, user_id INTEGER, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_works_flat ON works(flat_id);
CREATE INDEX IF NOT EXISTS ix_events_flat ON events(flat_id);
CREATE INDEX IF NOT EXISTS ix_photos_work ON photos(work_id);
"""


def _connect():
    if PG:
        import psycopg2
        import psycopg2.extras
        con = psycopg2.connect(URL.replace("postgres://", "postgresql://", 1),
                               cursor_factory=psycopg2.extras.RealDictCursor)
        return con
    con = sqlite3.connect(URL.replace("sqlite:///", ""))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def get():
    if "db" not in g:
        g.db = _connect()
    return g.db


def close(_exc=None):
    con = g.pop("db", None)
    if con is not None:
        con.close()


def _sql(s):
    return s.replace("?", "%s") if PG else s


def q(sql, args=(), one=False):
    cur = get().cursor()
    cur.execute(_sql(sql), args)
    rows = cur.fetchall()
    rows = [dict(r) for r in rows]
    return (rows[0] if rows else None) if one else rows


def x(sql, args=(), returning=False):
    cur = get().cursor()
    if returning:
        cur.execute(_sql(sql + " RETURNING id"), args)
        row = cur.fetchone()
        return row["id"] if PG else row[0]
    cur.execute(_sql(sql), args)
    return None


def commit():
    get().commit()


def init():
    con = _connect()
    ddl = SCHEMA.replace("{PK}", "SERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY AUTOINCREMENT") \
                .replace("{BLOB}", "BYTEA" if PG else "BLOB")
    cur = con.cursor()
    for stmt in [s.strip() for s in ddl.split(";") if s.strip()]:
        cur.execute(stmt)
    con.commit()
    con.close()


def blob(data):
    if PG:
        import psycopg2
        return psycopg2.Binary(data)
    return data
