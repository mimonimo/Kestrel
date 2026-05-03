"""Catalog of available vulnerability-lab images.

Each entry maps a high-level vuln class (e.g. ``xss``) to a runnable lab
container plus the metadata the AI payload-adapter needs to fit a generic
CVE payload to the lab's actual injection points.

Adding a lab: build the image (see ``sandbox-labs/README.md``) and append a
``LabDefinition`` here. The classifier maps CWE/keywords to the ``kind``
field.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class InjectionPoint:
    """Where in the lab's HTTP surface a payload can be delivered."""

    name: str
    method: str  # "GET" | "POST"
    path: str
    parameter: str
    location: str  # "query" | "form" | "json" | "header" | "path"
    response_kind: str  # "html-reflect" | "json-reflect" | "command-exec" | …
    notes: str = ""


@dataclass(frozen=True)
class LabDefinition:
    kind: str
    image: str
    description: str
    container_port: int  # internal port the lab listens on
    target_path: str  # the path to load in a browser to see the lab
    injection_points: list[InjectionPoint] = field(default_factory=list)
    build_hint: str = ""  # shown to the user when image is missing


LAB_CATALOG: dict[str, LabDefinition] = {
    "xss": LabDefinition(
        kind="xss",
        image="kestrel-lab-xss:latest",
        description="Reflected XSS — Flask 앱이 입력을 HTML에 그대로 삽입합니다.",
        container_port=5000,
        target_path="/",
        build_hint=(
            "docker build -t kestrel-lab-xss:latest sandbox-labs/xss-flask"
        ),
        injection_points=[
            InjectionPoint(
                name="echo_msg",
                method="GET",
                path="/echo",
                parameter="msg",
                location="query",
                response_kind="html-reflect",
                notes="응답 HTML의 <div id='echo'> 안에 입력이 그대로 출력됨.",
            ),
            InjectionPoint(
                name="search_q",
                method="GET",
                path="/search",
                parameter="q",
                location="query",
                response_kind="html-reflect",
                notes="응답 <h2> 안에 키워드가 출력됨.",
            ),
            InjectionPoint(
                name="comment_body",
                method="POST",
                path="/comment",
                parameter="body",
                location="form",
                response_kind="html-reflect",
                notes="form-encoded 본문을 .comment div 안에 출력.",
            ),
        ],
    ),
    "rce": LabDefinition(
        kind="rce",
        image="kestrel-lab-rce:latest",
        description="OS command injection — Flask 가 입력을 그대로 셸 명령어에 합칩니다.",
        container_port=5000,
        target_path="/",
        build_hint=(
            "docker build -t kestrel-lab-rce:latest sandbox-labs/rce-flask"
        ),
        injection_points=[
            InjectionPoint(
                name="ping_host",
                method="GET",
                path="/ping",
                parameter="host",
                location="query",
                response_kind="command-exec",
                notes="`ping -c 1 -W 1 <host>` 셸 합성 — `; cmd`/`$(cmd)` 류로 임의 명령 실행, 출력은 응답 <pre> 에.",
            ),
            InjectionPoint(
                name="lookup_domain",
                method="GET",
                path="/lookup",
                parameter="domain",
                location="query",
                response_kind="command-exec",
                notes="`nslookup <domain>` 으로 동일 패턴, stderr 도 본문에 함께 노출.",
            ),
        ],
    ),
    "sqli": LabDefinition(
        kind="sqli",
        image="kestrel-lab-sqli:latest",
        description="SQL injection — sqlite 백엔드, raw 쿼리에 입력 그대로 합쳐짐.",
        container_port=5000,
        target_path="/",
        build_hint=(
            "docker build -t kestrel-lab-sqli:latest sandbox-labs/sqli-flask"
        ),
        injection_points=[
            InjectionPoint(
                name="users_id",
                method="GET",
                path="/users",
                parameter="id",
                location="query",
                response_kind="sqli",
                notes="`SELECT … WHERE id = <id>` — boolean-blind / UNION / `randomblob` time-blind 모두 도달.",
            ),
            InjectionPoint(
                name="search_name",
                method="GET",
                path="/search",
                parameter="name",
                location="query",
                response_kind="sqli",
                notes="`WHERE name LIKE '%<name>%'` — quote escape + UNION 류로 다른 컬럼 추출 가능.",
            ),
        ],
    ),
    "ssti": LabDefinition(
        kind="ssti",
        image="kestrel-lab-ssti:latest",
        description="Server-Side Template Injection — Flask 가 입력을 jinja2 템플릿으로 그대로 평가.",
        container_port=5000,
        target_path="/",
        build_hint=(
            "docker build -t kestrel-lab-ssti:latest sandbox-labs/ssti-flask"
        ),
        injection_points=[
            InjectionPoint(
                name="greet_name",
                method="GET",
                path="/greet",
                parameter="name",
                location="query",
                response_kind="ssti",
                notes="`render_template_string('Hello, ' + name)` — `{{7*7}}` 가 49 로 평가됨.",
            ),
            InjectionPoint(
                name="render_tpl",
                method="GET",
                path="/render",
                parameter="tpl",
                location="query",
                response_kind="ssti",
                notes="입력을 통째로 템플릿으로 렌더링 — config/exception 객체 접근 가능.",
            ),
        ],
    ),
    "path-traversal": LabDefinition(
        kind="path-traversal",
        image="kestrel-lab-path:latest",
        description="Path traversal / LFI — Flask 가 입력을 정규화 없이 파일 경로로 사용.",
        container_port=5000,
        target_path="/",
        build_hint=(
            "docker build -t kestrel-lab-path:latest sandbox-labs/path-flask"
        ),
        injection_points=[
            InjectionPoint(
                name="file_name",
                method="GET",
                path="/file",
                parameter="name",
                location="query",
                response_kind="path-traversal",
                notes="`os.path.join('/app/uploads', name)` — `../../etc/passwd` 로 escape, 본문에 그대로 출력.",
            ),
            InjectionPoint(
                name="view_p",
                method="GET",
                path="/view",
                parameter="p",
                location="query",
                response_kind="path-traversal",
                notes="절대경로도 그대로 open — 임의 파일 읽기 (예: `/var/secret/flag.txt` 카나리).",
            ),
        ],
    ),
    "ssrf": LabDefinition(
        kind="ssrf",
        image="kestrel-lab-ssrf:latest",
        description="SSRF — Flask 가 사용자 URL 을 그대로 outbound HTTP GET.",
        container_port=5000,
        target_path="/",
        build_hint=(
            "docker build -t kestrel-lab-ssrf:latest sandbox-labs/ssrf-flask"
        ),
        injection_points=[
            InjectionPoint(
                name="fetch_url",
                method="GET",
                path="/fetch",
                parameter="url",
                location="query",
                response_kind="ssrf",
                notes="`requests.get(url, timeout=4)` — 격리 네트워크 내 다른 컨테이너 / 캐너리 URL 접근 가능.",
            ),
            InjectionPoint(
                name="preview_target",
                method="GET",
                path="/preview",
                parameter="target",
                location="query",
                response_kind="ssrf",
                notes="응답 본문 첫 200B 노출 — exfil 쉬운 변형.",
            ),
        ],
    ),
}


def get_lab(kind: str) -> LabDefinition | None:
    return LAB_CATALOG.get(kind.lower())
