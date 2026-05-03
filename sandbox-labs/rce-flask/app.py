"""Intentionally vulnerable Flask app — command injection (RCE) lab.

Two endpoints pass user input directly into a shell context. Used by the
Kestrel sandbox so AI-generated RCE payloads have a real target.

Do not run outside an isolated network.
"""
import subprocess
from flask import Flask, request

app = Flask(__name__)


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel RCE Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — RCE Lab</h1>
<p>의도적으로 OS command injection 에 취약한 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /ping?host=YOUR_PAYLOAD</code> — host 를 그대로 셸에 합쳐 ping 실행</li>
  <li><code>GET /lookup?domain=YOUR_PAYLOAD</code> — domain 을 nslookup 인자로 그대로 합침</li>
</ul>
</body></html>
"""


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/ping")
def ping() -> str:
    host = request.args.get("host", "127.0.0.1")
    # Intentional: shell=True + string concat. Classic command injection.
    out = subprocess.run(
        f"ping -c 1 -W 1 {host}",
        shell=True, capture_output=True, text=True, timeout=5,
    )
    return f"<pre>{out.stdout}{out.stderr}</pre>"


@app.get("/lookup")
def lookup() -> str:
    domain = request.args.get("domain", "example.com")
    out = subprocess.run(
        f"nslookup {domain} 2>&1 || true",
        shell=True, capture_output=True, text=True, timeout=5,
    )
    return f"<pre>{out.stdout}{out.stderr}</pre>"


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
