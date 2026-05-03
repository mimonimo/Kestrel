"""Intentionally vulnerable Flask app — path traversal / LFI lab.

The /file endpoint joins user input onto a base directory with no
normalization, so ``?name=../../etc/passwd`` reads system files.
PathTraversalCanaryProbe stamps a canary file via exec_in_lab and
verifies the lab returns it through this endpoint.

Do not run outside an isolated network.
"""
import os
from flask import Flask, request, abort

app = Flask(__name__)

BASE_DIR = "/app/uploads"
os.makedirs(BASE_DIR, exist_ok=True)
with open(os.path.join(BASE_DIR, "welcome.txt"), "w") as f:
    f.write("Hello from the uploads dir.\n")


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel Path Traversal Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — Path Traversal / LFI Lab</h1>
<p>의도적으로 path traversal 에 취약한 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /file?name=YOUR_PATH</code> — uploads 디렉터리에 그대로 join (정규화 X)</li>
  <li><code>GET /view?p=YOUR_PATH</code> — 절대경로도 그대로 open</li>
</ul>
</body></html>
"""


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/file")
def file_get() -> str:
    name = request.args.get("name", "welcome.txt")
    # Intentional: no normalization — `../../etc/passwd` escapes the base.
    target = os.path.join(BASE_DIR, name)
    try:
        with open(target, "r", errors="replace") as f:
            return f"<pre>{f.read()}</pre>"
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        return f"<pre>read error: {e}</pre>", 404


@app.get("/view")
def view() -> str:
    p = request.args.get("p", "/etc/hostname")
    try:
        with open(p, "r", errors="replace") as f:
            return f"<pre>{f.read()}</pre>"
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        return f"<pre>read error: {e}</pre>", 404


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
