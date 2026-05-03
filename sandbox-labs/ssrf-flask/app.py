"""Intentionally vulnerable Flask app — Server-Side Request Forgery (SSRF) lab.

The /fetch endpoint pulls whatever URL the user asks for. The
SsrfCanaryProbe spawns an in-network HTTP canary and verifies this lab
actually hits it when given the canary URL.

Do not run outside an isolated network — that's the whole point of the
sandbox bridge.
"""
import requests
from flask import Flask, request

app = Flask(__name__)


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel SSRF Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — SSRF Lab</h1>
<p>의도적으로 server-side request forgery 에 취약한 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /fetch?url=YOUR_URL</code> — url 을 그대로 outbound HTTP GET 으로 요청</li>
  <li><code>GET /preview?target=YOUR_URL</code> — target 의 첫 200 바이트를 본문에 노출</li>
</ul>
</body></html>
"""


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/fetch")
def fetch() -> str:
    url = request.args.get("url", "http://example.com/")
    try:
        # Intentional: no host whitelist, no scheme check, no DNS rebind
        # protection. The classic SSRF surface.
        r = requests.get(url, timeout=4)
        return f"<pre>status={r.status_code}\n{r.text[:500]}</pre>"
    except requests.RequestException as e:
        return f"<pre>fetch error: {e}</pre>", 502


@app.get("/preview")
def preview() -> str:
    target = request.args.get("target", "http://example.com/")
    try:
        r = requests.get(target, timeout=4)
        return r.text[:200]
    except requests.RequestException as e:
        return f"preview error: {e}", 502


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
