"""CISA SSVC 기반 "권장 대응 기한(Remediation Timeline)" 도출.

취약점의 신호를 CISA 의 *Remediation Timelines* 결정 트리에 대입해 구체적인
대응 기한(3/14/60일 또는 차기 업그레이드 시)과 그 근거를 만든다. 입력 4축:

    - Exploitation(악용)   ← KEV 등재 여부          (실측)
    - Automatable(자동화)  ← CVSS 벡터 + EPSS        (이론 + 예측)
    - Technical Impact     ← CVSS 영향 메트릭(C/I/A)  (이론)
    - Publicly Exposed     ← CVSS 공격 벡터(AV) 프록시 (기본 노출=worst case)

Kestrel 의 3대 축(CVSS 이론 · EPSS 예측 · KEV 실측)을 그대로 재사용하므로
기존 우선순위 모델의 *연장*이지 별도 시스템이 아니다.

노출(Exposure) 처리 = 제품 결정 A+B:
    - 기본값은 "노출됨"(worst case, A).
    - CVSS Attack Vector 로 보정(B): N(네트워크)/A(인접) ⇒ 노출, L(로컬)/P(물리)
      ⇒ 비노출. 벡터가 없으면 보수적으로 노출로 둔다.
"""
from __future__ import annotations

from dataclasses import dataclass


def parse_cvss_vector(vector: str | None) -> dict[str, str]:
    """"CVSS:3.1/AV:N/AC:L/..." → {"AV":"N","AC":"L",...}. 모르면 빈 dict."""
    if not vector:
        return {}
    out: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        key = key.strip()
        val = val.strip().upper()
        if not key or key.upper().startswith("CVSS") or not val:
            continue
        out[key] = val
    return out


@dataclass(frozen=True)
class SsvcInputs:
    kev: bool
    automatable: bool
    total_impact: bool
    exposed: bool
    exposure_basis: str  # 노출 판단 근거: "av:N" / "default(no-vector)" 등


# EPSS 임계 — 이 이상이면 야생에서 자동화 대량 악용 가능성이 높다고 보고
# Automatable=yes 로 승급(우선순위 규칙의 epss_high=0.5 와 동일 기준).
_EPSS_AUTOMATABLE = 0.5


def derive_inputs(
    *,
    cvss_vector: str | None,
    cvss_score: float | None,
    epss_score: float | None,
    kev_listed: bool,
) -> SsvcInputs:
    m = parse_cvss_vector(cvss_vector)
    av = m.get("AV")

    # ── Exposure (A+B) ──────────────────────────────────────────
    if av in {"N", "A"}:
        exposed, basis = True, f"av:{av}"
    elif av in {"L", "P"}:
        exposed, basis = False, f"av:{av}"
    else:
        exposed, basis = True, "default(no-vector)"  # worst-case 기본

    # ── Automatable ─────────────────────────────────────────────
    # 정찰~악용 단계가 자동화 가능한가. CVSS 로 근사:
    #   v3/3.1: AV:N · AC:L · PR:N · UI:N
    #   v4    : AV:N · AC:L · AT:N · PR:N · UI:N
    #   v2    : AV:N · AC:L · Au:N
    # 또는 EPSS 가 높으면(야생 자동 악용) 자동화 가능으로 승급.
    auto_by_vector = False
    if av == "N":
        ac_low = m.get("AC") == "L"
        pr_none = m.get("PR", "N") == "N"  # v2 엔 PR 없음 → 통과
        ui_none = m.get("UI", "N") == "N"
        at_none = m.get("AT", "N") == "N"  # v4 only
        au_none = m.get("Au", "N") == "N"  # v2 only
        auto_by_vector = ac_low and pr_none and ui_none and at_none and au_none
    auto_by_epss = epss_score is not None and epss_score >= _EPSS_AUTOMATABLE
    automatable = bool(auto_by_vector or auto_by_epss)

    # ── Technical Impact (Total/Partial) ────────────────────────
    # Total = 완전 장악. CVSS 영향 메트릭이 모두 최고치일 때.
    #   v3/3.1: C/I/A = H,  v4: VC/VI/VA = H,  v2: C/I/A = C(Complete)
    # 벡터가 없으면 점수로 폴백(>= 9.0 ⇒ Total).
    total_impact = False
    if {"C", "I", "A"} <= m.keys():
        total_impact = m["C"] in {"H", "C"} and m["I"] in {"H", "C"} and m["A"] in {"H", "C"}
    elif {"VC", "VI", "VA"} <= m.keys():
        total_impact = m["VC"] == "H" and m["VI"] == "H" and m["VA"] == "H"
    elif cvss_score is not None:
        total_impact = cvss_score >= 9.0

    return SsvcInputs(
        kev=bool(kev_listed),
        automatable=automatable,
        total_impact=total_impact,
        exposed=exposed,
        exposure_basis=basis,
    )


# 기한별 한국어 라벨 + 권장 조치.
def _outcome(due_days: int | None, forensic: bool = False) -> dict:
    if due_days is None:
        label = "차기 업그레이드 시"
        action = "별도 긴급 패치 불필요 — 정기 시스템 업그레이드 주기에 맞춰 조치"
    elif due_days <= 3:
        label = "3일 이내"
        action = (
            "즉시 패치 + 침해 여부 포렌식 분석"
            if forensic
            else "즉시(3일 이내) 패치 — 최우선 대응"
        )
    elif due_days <= 14:
        label = "14일 이내"
        action = "2주 이내 패치 — 우선 조치 대상"
    else:
        label = f"{due_days}일 이내"
        action = "계획된 패치 주기 내 조치(60일 이내)"
    return {"due_days": due_days, "label": label, "forensic_triage": forensic, "action": action}


def decide(i: SsvcInputs) -> dict:
    """CISA Remediation Timelines 결정 트리."""
    if i.exposed:
        if i.kev:
            if i.automatable:
                return _outcome(3, forensic=i.total_impact)
            return _outcome(3, forensic=True) if i.total_impact else _outcome(14)
        # KEV 아님
        if i.automatable:
            return _outcome(3) if i.total_impact else _outcome(14)
        return _outcome(14) if i.total_impact else _outcome(60)
    # 비노출
    if i.kev:
        if i.automatable:
            return _outcome(3, forensic=True) if i.total_impact else _outcome(14)
        return _outcome(14)
    if i.automatable:
        return _outcome(60)
    return _outcome(None)


def _rationale(i: SsvcInputs) -> str:
    parts = [
        "KEV 등재" if i.kev else "KEV 미등재",
        "자동화 가능" if i.automatable else "자동화 어려움",
        "완전 장악" if i.total_impact else "부분 영향",
        "외부 노출" if i.exposed else "내부 한정",
    ]
    return " · ".join(parts)


def build_remediation(
    *,
    cvss_vector: str | None,
    cvss_score: float | None,
    epss_score: float | None,
    kev_listed: bool,
) -> dict:
    """신호 → 권장 대응 기한 dict(VulnerabilityDetail.remediation 용)."""
    i = derive_inputs(
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        epss_score=epss_score,
        kev_listed=kev_listed,
    )
    out = decide(i)
    out.update(
        kev=i.kev,
        automatable=i.automatable,
        total_impact=i.total_impact,
        exposed=i.exposed,
        exposure_basis=i.exposure_basis,
        rationale=_rationale(i),
    )
    return out


def remediation_for(vuln) -> dict:
    """ORM Vulnerability → 권장 대응 기한 dict."""
    score = vuln.cvss_score
    return build_remediation(
        cvss_vector=getattr(vuln, "cvss_vector", None),
        cvss_score=float(score) if score is not None else None,
        epss_score=getattr(vuln, "epss_score", None),
        kev_listed=bool(getattr(vuln, "kev_listed", False)),
    )
