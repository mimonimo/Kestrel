"""원본 소스(raw_data)에서 상세 보강 정보를 추출한다 — 외부 재요청 없음.

CVE 상세 페이지에서 "내 사이트만 봐도 분석 가능"하도록, NVD 원본 payload 에
들어 있는 약점(CWE)·강화 레퍼런스(tags/source)·CVSS 메트릭(여러 버전 + exploit
maturity + 서브스코어)을 끌어온다. NVD 스키마(raw_data.cve)를 1차로 처리하고,
없으면 모델에 이미 있는 데이터(types / references / cvss)로 폴백한다.
"""
from __future__ import annotations

import re
from typing import Any

from app.schemas.vulnerability import (
    CvssMetricOut,
    EnrichedRefOut,
    EnrichmentOut,
    WeaknessOut,
)

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

# NVD metrics 키 → 표시용 버전 라벨 (선호 순서: 4.0 → 3.1 → 3.0 → 2.0)
_METRIC_KEYS: list[tuple[str, str]] = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
]


def _cwe_url(cwe_id: str) -> str | None:
    m = re.search(r"\d+", cwe_id)
    return f"https://cwe.mitre.org/data/definitions/{m.group()}.html" if m else None


def _weaknesses(cve: dict | None, vuln) -> list[WeaknessOut]:
    # cwe_id → 사람이 읽는 분류명 (우리 types 분류 재사용).
    name_by_cwe = {
        (t.cwe_id or "").upper(): t.name
        for t in (getattr(vuln, "types", None) or [])
        if getattr(t, "cwe_id", None)
    }
    out: list[WeaknessOut] = []
    seen: set[str] = set()

    if isinstance(cve, dict):
        for w in cve.get("weaknesses") or []:
            for d in w.get("description") or []:
                for cwe in _CWE_RE.findall(str(d.get("value") or "")):
                    cwe = cwe.upper()
                    if cwe in seen or cwe == "CWE-NONE":
                        continue
                    seen.add(cwe)
                    out.append(
                        WeaknessOut(cwe_id=cwe, name=name_by_cwe.get(cwe), url=_cwe_url(cwe))
                    )

    # 폴백 — raw_data 에 weaknesses 가 없으면 우리 분류(types)의 CWE 사용.
    if not out:
        for t in getattr(vuln, "types", None) or []:
            cwe = (getattr(t, "cwe_id", None) or "").upper()
            if cwe and cwe not in seen:
                seen.add(cwe)
                out.append(WeaknessOut(cwe_id=cwe, name=t.name, url=_cwe_url(cwe)))
    return out


def _references(cve: dict | None) -> list[EnrichedRefOut]:
    out: list[EnrichedRefOut] = []
    seen: set[str] = set()
    if isinstance(cve, dict):
        for r in cve.get("references") or []:
            url = r.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            out.append(
                EnrichedRefOut(
                    url=url,
                    tags=[str(t) for t in (r.get("tags") or [])],
                    source=r.get("source"),
                )
            )
    return out


def _f(v: Any) -> float | None:
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _metrics(cve: dict | None) -> list[CvssMetricOut]:
    out: list[CvssMetricOut] = []
    if not isinstance(cve, dict):
        return out
    metrics = cve.get("metrics") or {}
    for key, ver in _METRIC_KEYS:
        for entry in metrics.get(key) or []:
            if not isinstance(entry, dict):
                continue
            cd = entry.get("cvssData") or {}
            out.append(
                CvssMetricOut(
                    version=str(cd.get("version") or ver),
                    vector=cd.get("vectorString"),
                    base_score=_f(cd.get("baseScore")),
                    base_severity=cd.get("baseSeverity") or entry.get("baseSeverity"),
                    source=entry.get("source"),
                    kind=entry.get("type"),
                    exploitability_score=_f(entry.get("exploitabilityScore")),
                    impact_score=_f(entry.get("impactScore")),
                    exploit_maturity=cd.get("exploitMaturity"),
                )
            )
    return out


def build_enrichment(vuln) -> EnrichmentOut | None:
    """vuln.raw_data + 모델 데이터에서 보강 정보를 구성. 실패해도 None 반환(상세 비차단)."""
    try:
        raw = getattr(vuln, "raw_data", None) or {}
        cve = raw.get("cve") if isinstance(raw, dict) else None
        weaknesses = _weaknesses(cve, vuln)
        references = _references(cve)
        metrics = _metrics(cve)
        if not weaknesses and not references and not metrics:
            return None
        return EnrichmentOut(weaknesses=weaknesses, references=references, metrics=metrics)
    except Exception:  # noqa: BLE001 — 보강은 best-effort, 상세 응답을 막지 않는다.
        return None
