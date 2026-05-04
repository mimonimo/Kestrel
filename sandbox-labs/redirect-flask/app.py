"""Intentionally vulnerable Flask app — open redirect lab.

Both endpoints pass user-supplied URLs straight to ``flask.redirect()``
with no allow-list, scheme, or origin check. The OpenRedirectProbe
sends a unique nonce URL and verifies the Location header echoes it.

Do not run outside an isolated network.
"""
from flask import Flask, redirect, request

app = Flask(__name__)


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel Open Redirect Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — Open Redirect Lab</h1>
<p>의도적으로 사용자 입력 URL 로 무조건 redirect 하는 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /redirect?url=YOUR_URL</code> — 302 + Location: &lt;url&gt;</li>
  <li><code>GET /go?next=YOUR_URL</code> — 동일 패턴, 다른 파라미터 이름</li>
</ul>
</body></html>
"""


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # Intentional: no scheme/origin/allow-list check. Whatever the user
    # sends becomes the Location header.
    return redirect(url, code=302)


@app.get("/go")
def go_next():
    nxt = request.args.get("next", "/")
    return redirect(nxt, code=302)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
