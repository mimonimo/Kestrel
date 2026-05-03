"""Intentionally vulnerable Flask app — SQL injection lab (sqlite-backed).

The /users endpoint concatenates the user-supplied id into a SELECT
statement with no parameterization. SQLite supports randomblob(N) which
the SqliTimeBlindProbe's payload bank uses for time-blind detection
(``1' AND randomblob(2e8)--``). Boolean-blind probes also work.

Do not run outside an isolated network.
"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)

DB_PATH = "/tmp/kestrel-sqli.db"


def _seed_db() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    cur.executemany(
        "INSERT INTO users (id, name, role) VALUES (?, ?, ?)",
        [(1, "alice", "admin"), (2, "bob", "user"), (3, "carol", "user")],
    )
    con.commit()
    con.close()


_seed_db()


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel SQLi Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — SQLi Lab</h1>
<p>의도적으로 SQL injection 에 취약한 데모 엔드포인트입니다 (sqlite).</p>
<ul>
  <li><code>GET /users?id=YOUR_PAYLOAD</code> — id 를 raw 쿼리에 그대로 합침</li>
  <li><code>GET /search?name=YOUR_PAYLOAD</code> — name 을 LIKE 절에 그대로 합침</li>
</ul>
</body></html>
"""


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/users")
def users() -> str:
    user_id = request.args.get("id", "1")
    # Intentional: string concat into SQL. Boolean-blind, UNION-based,
    # and CPU-burn (randomblob) payloads all reach the engine.
    sql = f"SELECT id, name, role FROM users WHERE id = {user_id}"
    con = sqlite3.connect(DB_PATH)
    try:
        rows = con.execute(sql).fetchall()
        body = "<table border=1>"
        for r in rows:
            body += "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>"
        body += "</table>"
        return body
    except sqlite3.Error as e:
        return f"<pre>SQL error: {e}\nquery: {sql}</pre>", 500
    finally:
        con.close()


@app.get("/search")
def search() -> str:
    name = request.args.get("name", "")
    sql = f"SELECT id, name FROM users WHERE name LIKE '%{name}%'"
    con = sqlite3.connect(DB_PATH)
    try:
        rows = con.execute(sql).fetchall()
        return "<ul>" + "".join(f"<li>{r[0]}: {r[1]}</li>" for r in rows) + "</ul>"
    except sqlite3.Error as e:
        return f"<pre>SQL error: {e}\nquery: {sql}</pre>", 500
    finally:
        con.close()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
