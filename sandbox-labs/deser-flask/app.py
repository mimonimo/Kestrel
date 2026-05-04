"""Intentionally vulnerable Flask app — insecure deserialization lab.

Both endpoints accept a base64-encoded blob and feed it to ``pickle.loads``
without any signature, type, or sandboxing check. The
DeserializationCanaryProbe constructs a pickle gadget whose
``__reduce__`` runs ``os.system('printf %s VALUE > PATH')`` and verifies
the canary file via ``exec_in_lab``.

Do not run outside an isolated network.
"""
import base64
import binascii
import pickle  # noqa: S403 — vulnerable on purpose
from flask import Flask, request

app = Flask(__name__)


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel Insecure Deserialization Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — Insecure Deserialization Lab</h1>
<p>의도적으로 base64 → pickle.loads 를 그대로 호출하는 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /load?data=BASE64_PICKLE</code> — query string 기반 (작은 페이로드)</li>
  <li><code>POST /load</code> body=BASE64_PICKLE — 큰 페이로드용</li>
</ul>
</body></html>
"""


def _vulnerable_deser(blob_b64: str) -> str:
    try:
        raw = base64.b64decode(blob_b64, validate=False)
    except (ValueError, binascii.Error) as e:
        return f"<pre>base64 decode error: {e}</pre>"
    try:
        # Intentional: pickle.loads on attacker-controlled bytes is RCE
        # by design. The probe's __reduce__ gadget runs at this line.
        obj = pickle.loads(raw)  # noqa: S301
    except Exception as e:  # noqa: BLE001 — show whatever pickle complained about
        return f"<pre>unpickle error: {type(e).__name__}: {e}</pre>"
    return f"<pre>unpickled type={type(obj).__name__} repr={obj!r}</pre>"


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/load")
def load_get() -> str:
    blob = request.args.get("data", "")
    return _vulnerable_deser(blob)


@app.post("/load")
def load_post() -> str:
    blob = request.get_data(as_text=True) or request.form.get("data", "")
    return _vulnerable_deser(blob)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
