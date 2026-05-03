"""Intentionally vulnerable Flask app — Server-Side Template Injection (SSTI) lab.

The /greet endpoint feeds user input directly into Jinja2's
render_template_string. Classic SSTI payloads like ``{{7*7}}`` evaluate
to 49 in the response — the SstiArithmeticProbe checks exactly that.

Do not run outside an isolated network.
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel SSTI Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — SSTI Lab</h1>
<p>의도적으로 jinja2 SSTI 에 취약한 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /greet?name=YOUR_PAYLOAD</code> — name 을 jinja2 템플릿에 그대로 합침</li>
  <li><code>GET /render?tpl=YOUR_PAYLOAD</code> — 전체 템플릿 문자열을 그대로 평가</li>
</ul>
</body></html>
"""


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/greet")
def greet() -> str:
    name = request.args.get("name", "world")
    # Intentional: user input concatenated into a template string and
    # rendered. Standard SSTI surface — {{7*7}} → 49.
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.get("/render")
def render() -> str:
    tpl = request.args.get("tpl", "(empty)")
    return render_template_string(tpl)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
