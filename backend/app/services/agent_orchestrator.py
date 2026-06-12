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
from app.models import AnalysisResult, Comment, User, Vulnerability
from app.services.ai_analyzer import (
    AiAnalyzerNotConfigured,
    analyze_vulnerability,
    call_llm,
)

log = get_logger(__name__)

_MAX_PER_CYCLE = 3          # 한 사이클(잡 1회) 전체 분석 상한 — 비용·부하 보호
_PER_AGENT_PER_CYCLE = 1    # 한 사이클당 에이전트 1건씩 (공평 분배)
_DISCUSS_CVES = 3           # 사이클당 토론 대상 CVE 수
_MAX_COMMENTS_PER_CYCLE = 2 # 사이클당 토론 댓글 상한 (비용)
_MAX_THREAD = 3             # CVE 1건당 에이전트 댓글 총 상한 (루프 방지)

_COMMENT_SYSTEM = (
    "당신은 보안 분석 커뮤니티에서 활동하는 AI 분석가입니다. 다른 분석가가 올린 분석에 "
    "본인 관점의 짧은 코멘트(2~3문장, 한국어 존댓말)를 답니다. 새로운 통찰·이견·보완점·"
    "검증 포인트를 간결하게. 사과·거부·서론 없이 본론만. 마크다운/JSON/코드펜스 금지, "
    "일반 문장으로만 작성하세요."
)


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

        # 분석에 이어 에이전트 토론(다른 페르소나가 댓글로 1~2턴).
        try:
            await _run_discussion(db, agents)
        except Exception:  # noqa: BLE001
            await db.rollback()
            log.exception("agent.discussion_failed")
    if produced:
        log.info("agent.cycle_done", produced=produced)


async def _run_discussion(db, agents: list) -> None:
    """최근 에이전트 분석이 달린 CVE 에, 다른 페르소나 에이전트가 짧은 코멘트를
    달아 토론을 만든다. CVE당 총 _MAX_THREAD, 사이클당 _MAX_COMMENTS_PER_CYCLE 상한 +
    한 에이전트는 CVE당 1회만 → 무한 핑퐁 방지."""
    if len(agents) < 2:
        return  # 토론하려면 최소 2개 페르소나
    agent_ids = [a.id for a in agents]
    since = datetime.now(timezone.utc) - timedelta(hours=48)

    rows = (
        await db.execute(
            select(AnalysisResult.cve_id, func.max(AnalysisResult.created_at).label("ts"))
            .where(AnalysisResult.category == "agent", AnalysisResult.created_at >= since)
            .group_by(AnalysisResult.cve_id)
            .order_by(func.max(AnalysisResult.created_at).desc())
            .limit(_DISCUSS_CVES)
        )
    ).all()

    posted = 0
    for cve_id, _ts in rows:
        if posted >= _MAX_COMMENTS_PER_CYCLE:
            break
        vuln = await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
        if vuln is None:
            continue
        # CVE 스레드의 에이전트 댓글 총 수 (루프 상한)
        thread_n = await db.scalar(
            select(func.count(Comment.id)).where(
                Comment.vulnerability_id == vuln.id, Comment.user_id.in_(agent_ids)
            )
        )
        if int(thread_n or 0) >= _MAX_THREAD:
            continue
        # 이 CVE 의 분석 작성자(자기 글엔 댓글 안 달게 제외)
        author_id = await db.scalar(
            select(AnalysisResult.user_id)
            .where(AnalysisResult.cve_id == cve_id, AnalysisResult.category == "agent")
            .order_by(AnalysisResult.created_at.desc())
            .limit(1)
        )
        prior_md = await db.scalar(
            select(AnalysisResult.result_md)
            .where(AnalysisResult.cve_id == cve_id, AnalysisResult.category == "agent")
            .order_by(AnalysisResult.created_at.desc())
            .limit(1)
        )
        # 아직 이 CVE 에 댓글 안 단 다른 페르소나 1명 선정
        for peer in agents:
            if peer.id == author_id or peer.owner_user_id is None:
                continue
            already = await db.scalar(
                select(func.count(Comment.id)).where(
                    Comment.vulnerability_id == vuln.id, Comment.user_id == peer.id
                )
            )
            if int(already or 0) > 0:
                continue
            try:
                system = _COMMENT_SYSTEM
                if peer.persona_prompt:
                    system = peer.persona_prompt.strip() + "\n\n" + _COMMENT_SYSTEM
                user_msg = (
                    f"CVE: {vuln.cve_id}\n제목: {vuln.title}\n\n"
                    f"다른 분석가의 분석 요약:\n{(prior_md or '')[:600]}\n\n"
                    "이 취약점/분석에 대해 당신 관점의 코멘트를 2~3문장으로 남겨주세요."
                )
                text = await call_llm(db, system, user_msg, force_json=False, user_id=peer.owner_user_id)
                text = (text or "").strip()
                if not text:
                    continue
                name = f"{peer.avatar_emoji or '🤖'} {peer.nickname or peer.username}"
                db.add(
                    Comment(
                        user_id=peer.id,
                        author_name=name[:64],
                        content=text[:4000],
                        vulnerability_id=vuln.id,
                    )
                )
                await db.commit()
                posted += 1
                log.info("agent.comment_posted", agent_id=str(peer.id), cve_id=cve_id)
            except AiAnalyzerNotConfigured:
                continue
            except Exception:  # noqa: BLE001
                await db.rollback()
                log.exception("agent.comment_failed", agent_id=str(peer.id), cve_id=cve_id)
            break  # CVE당 사이클 1명만
