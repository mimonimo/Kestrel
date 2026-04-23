"""Intentionally vulnerable Flask app — reflected XSS lab for the Kestrel sandbox.

Two endpoints reflect user input directly into the HTML response with no
escaping. Used by the sandbox feature to give AI-generated XSS payloads a
real target to fire against.

Do not run outside an isolated network.
"""
from flask import Flask, request

app = Flask(__name__)


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel XSS Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — XSS Lab</h1>
<p>의도적으로 reflected XSS에 취약한 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /echo?msg=YOUR_PAYLOAD</code> — 쿼리 파라미터를 응답 본문에 그대로 출력</li>
  <li><code>GET /search?q=YOUR_PAYLOAD</code> — 검색 결과 페이지에 키워드를 그대로 삽입</li>
  <li><code>POST /comment</code> (form: <code>body=YOUR_PAYLOAD</code>) — 본문을 그대로 출력</li>
</ul>
</body></html>
"""


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/echo")
def echo() -> str:
    msg = request.args.get("msg", "")
    # Intentional: no escaping. Direct reflection.
    return f"<!doctype html><html><body><div id='echo'>{msg}</div></body></html>"


@app.get("/search")
def search() -> str:
    q = request.args.get("q", "")
    return (
        "<!doctype html><html><body>"
        f"<h2>검색: {q}</h2>"
        "<p>일치하는 결과가 없습니다.</p>"
        "</body></html>"
    )


@app.post("/comment")
def comment() -> str:
    body = request.form.get("body", "")
    return (
        "<!doctype html><html><body>"
        "<h2>새 댓글</h2>"
        f"<div class='comment'>{body}</div>"
        "</body></html>"
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
