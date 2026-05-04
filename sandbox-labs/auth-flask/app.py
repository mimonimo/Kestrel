"""Intentionally vulnerable Flask app — auth-bypass / broken-access-control lab.

Two classic shapes the AuthBypassDifferentialProbe knows how to verify:

* ``/admin?role=`` — authentication-bypass via privilege param. Anonymous
  request returns 401, ``?role=admin`` (one of the probe's bypass values)
  returns the protected dashboard with a noticeably larger body.
* ``/profile?id=`` — IDOR via direct object reference. Any non-empty id
  returns the corresponding user's profile with no ownership check.

Do not run outside an isolated network.
"""
from flask import Flask, request

app = Flask(__name__)


# Hardcoded user table — IDOR target. The ownership check is what's
# missing: real apps would compare ``id`` against the session user.
USERS = {
    "1": {"name": "alice", "email": "alice@example.com", "ssn": "111-22-3333"},
    "2": {"name": "bob",   "email": "bob@example.com",   "ssn": "444-55-6666"},
    "3": {"name": "carol", "email": "carol@example.com", "ssn": "777-88-9999"},
}


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel Auth-Bypass Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — Auth-Bypass / Broken Access Control Lab</h1>
<p>의도적으로 권한 검증이 망가진 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /admin?role=YOUR_PAYLOAD</code> — role 값에 따라 보호된 본문 노출 여부 결정</li>
  <li><code>GET /profile?id=YOUR_PAYLOAD</code> — 임의 id 값으로 다른 사용자 프로필 조회 (IDOR)</li>
</ul>
</body></html>
"""


# Body templates — the protected page must be meaningfully larger than
# the unauthorized response so AuthBypassDifferentialProbe's 30%
# body-diff threshold passes.
ADMIN_DASHBOARD = """<!doctype html><html><body>
<h1>Admin Dashboard</h1>
<p>Welcome to the protected administration interface.</p>
<ul>
  <li>Active users: 3</li>
  <li>Pending tickets: 17</li>
  <li>Revenue YTD: $1,234,567</li>
  <li>System version: kestrel-lab-auth/1.0</li>
</ul>
<p>Sensitive controls — only intended for authenticated administrators.</p>
</body></html>"""

UNAUTHORIZED = "<h1>401 Unauthorized</h1><p>Access denied.</p>"


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/admin")
def admin() -> tuple[str, int]:
    role = request.args.get("role", "")
    # Intentional: trusts the request param without any session check.
    # Only the literal value "admin" unlocks the dashboard, so empty /
    # random values get the unauthorized shape and the probe's 7-payload
    # bank discovers the bypass.
    if role == "admin":
        return ADMIN_DASHBOARD, 200
    return UNAUTHORIZED, 401


@app.get("/profile")
def profile() -> tuple[str, int]:
    # IDOR: returns any user's profile by id with no ownership check.
    user_id = request.args.get("id", "")
    if not user_id:
        return UNAUTHORIZED, 401
    user = USERS.get(user_id)
    if user is None:
        return f"<p>No such user: {user_id}</p>", 404
    return (
        "<!doctype html><html><body>"
        f"<h1>Profile #{user_id}</h1>"
        f"<dl>"
        f"<dt>Name</dt><dd>{user['name']}</dd>"
        f"<dt>Email</dt><dd>{user['email']}</dd>"
        f"<dt>SSN</dt><dd>{user['ssn']}</dd>"
        f"</dl></body></html>",
        200,
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
