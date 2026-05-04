"""Intentionally vulnerable Flask app — XXE (XML External Entity) lab.

Two endpoints feed user XML straight into lxml's parser with external
entity resolution explicitly enabled. The XxeCanaryProbe stamps a
canary file via exec_in_lab and verifies the lab's response includes
its content via ``<!DOCTYPE [<!ENTITY x SYSTEM "file:///path">]>``.

Do not run outside an isolated network.
"""
from flask import Flask, request
from lxml import etree

app = Flask(__name__)


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Kestrel XXE Lab</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 2rem auto;">
<h1>Kestrel — XXE Lab</h1>
<p>의도적으로 외부 엔티티 평가가 켜진 데모 엔드포인트입니다.</p>
<ul>
  <li><code>GET /parse?xml=YOUR_PAYLOAD</code> — query string XML 을 외부 엔티티 평가하며 파싱</li>
  <li><code>POST /parse</code> body=XML — 동일하나 큰 페이로드용</li>
</ul>
</body></html>
"""


def _vulnerable_parse(xml_text: str) -> str:
    # Intentional: resolve_entities=True is the legacy lxml default but
    # we set it explicitly so the file's intent is unambiguous. no_network
    # stays True so file:// is the only reachable scheme — that matches the
    # sandbox network policy and what XxeCanaryProbe sends.
    parser = etree.XMLParser(
        resolve_entities=True,
        no_network=True,
        load_dtd=True,
    )
    try:
        root = etree.fromstring(xml_text.encode("utf-8"), parser=parser)
    except etree.XMLSyntaxError as e:
        return f"<pre>parse error: {e}</pre>"
    # Echo the parsed tree's text content — that's where the resolved
    # entity value ends up after &x; expansion.
    return f"<pre>{etree.tostring(root, encoding='unicode', method='xml')}</pre>"


@app.get("/")
def index() -> str:
    return INDEX_HTML


@app.get("/parse")
def parse_get() -> str:
    xml = request.args.get("xml", "<root/>")
    return _vulnerable_parse(xml)


@app.post("/parse")
def parse_post() -> str:
    xml = request.get_data(as_text=True) or request.form.get("xml", "<root/>")
    return _vulnerable_parse(xml)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
