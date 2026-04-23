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
}


def get_lab(kind: str) -> LabDefinition | None:
    return LAB_CATALOG.get(kind.lower())
