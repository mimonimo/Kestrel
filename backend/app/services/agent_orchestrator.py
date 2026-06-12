"""AI 에이전트 오케스트레이터 — 활성 에이전트가 우선순위 CVE 를 자동 분석하고
커뮤니티(공개 분석 피드)에 공유한다.

설계:
- 에이전트 = 특수 User row(is_agent). 분석은 *소유자(owner)* 의 Claude 크레딧으로
  실행하고, 결과 AnalysisResult 는 *에이전트* 명의(user_id=agent.id)로 저장한다.
- 우선순위: KEV 또는 CVSS 높은 것 우선, 그 에이전트가 아직 분석하지 않은 CVE.
- 비용/부하 통제: 에이전트별 일일 상한(agent_daily_limit), 한 사이클당 에이전트당 1건,
  사이클 전체 상한(_MAX_PER_CYCLE). 한 건 실패가 배치를 멈추지 않게 격리.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import exists, func, or_, select

from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models import AnalysisResult, User, Vulnerability
from app.services.ai_analyzer import AiAnalyzerNotConfigured, analyze_vulnerability

log = get_logger(__name__)

_MAX_PER_CYCLE = 3          # 한 사이클(잡 1회) 전체 분석 상한 — 비용·부하 보호
_PER_AGENT_PER_CYCLE = 1    # 한 사이클당 에이전트 1건씩 (공평 분배)


def _result_md(result) -> str:
    lines = ["## 공격 방법", "", result.attack_method, "", "## 페이로드 예시", ""]
    for idx, p in enumerate(result.payload_examples, 1):
        lines += [f"### 예시 {idx}", "", "```", p, "```", ""]
    lines += ["## 완화 방안", ""]
    lines += [f"- {m}" for m in result.mitigations]
    return "\n".join(lines)


async def _pick_cves(db, agent_id, limit: int) -> list[Vulnerability]:
    """그 에이전트가 아직 분석하지 않은 우선순위 CVE 선택."""
    already = select(AnalysisResult.id).where(
        AnalysisResult.user_id == agent_id,
        AnalysisResult.cve_id == Vulnerability.cve_id,
    )
    stmt = (
        select(Vulnerability)
        .where(
            or_(Vulnerability.kev_listed.is_(True), Vulnerability.cvss_score >= 8.0),
            ~exists(already),
        )
        .order_by(
            Vulnerability.kev_listed.desc(),
            Vulnerability.cvss_score.desc().nulls_last(),
            Vulnerability.published_at.desc().nulls_last(),
        )
        .limit(limit)
    )
    return list((await db.execute(stmt)).scalars().unique().all())


async def run_agent_cycle() -> None:
    """스케줄러가 주기적으로 호출. 활성 에이전트별로 1건씩 분석·공유."""
    produced = 0
    async with SessionLocal() as db:
        agents = (
            await db.execute(
                select(User).where(
                    User.is_agent.is_(True),
                    User.agent_enabled.is_(True),
                    User.owner_user_id.is_not(None),
                )
            )
        ).scalars().all()

        if not agents:
            return

        today = datetime.now(timezone.utc) - timedelta(hours=24)
        for agent in agents:
            if produced >= _MAX_PER_CYCLE:
                break
            # 일일 상한 체크 (최근 24시간 기준)
            done = await db.scalar(
                select(func.count(AnalysisResult.id)).where(
                    AnalysisResult.user_id == agent.id,
                    AnalysisResult.created_at >= today,
                )
            )
            budget = int(agent.agent_daily_limit or 5) - int(done or 0)
            if budget <= 0:
                continue

            pick_n = min(_PER_AGENT_PER_CYCLE, budget, _MAX_PER_CYCLE - produced)
            cves = await _pick_cves(db, agent.id, pick_n)
            for vuln in cves:
                try:
                    result = await analyze_vulnerability(
                        db, vuln, user_id=agent.owner_user_id, extra_system=agent.persona_prompt
                    )
                    label = agent.persona or agent.nickname or "AI 에이전트"
                    db.add(
                        AnalysisResult(
                            cve_id=vuln.cve_id,
                            user_id=agent.id,
                            category="agent",
                            title=f"{label} 분석 — {vuln.cve_id}",
                            prompt_md=None,
                            result_md=_result_md(result),
                            visibility="public",
                        )
                    )
                    await db.commit()
                    produced += 1
                    log.info("agent.analysis_published", agent_id=str(agent.id), cve_id=vuln.cve_id)
                except AiAnalyzerNotConfigured:
                    # 소유자가 Claude 미연동 — 조용히 스킵(다음 사이클에 재시도).
                    log.info("agent.skip_no_credential", agent_id=str(agent.id))
                    break
                except Exception:  # noqa: BLE001 — 한 건 실패가 배치를 멈추지 않게
                    await db.rollback()
                    log.exception("agent.analysis_failed", agent_id=str(agent.id), cve_id=vuln.cve_id)
    if produced:
        log.info("agent.cycle_done", produced=produced)
