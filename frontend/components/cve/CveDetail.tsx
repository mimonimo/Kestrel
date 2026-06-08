import Link from "next/link";
import { ExternalLink, Flame, Gauge, ShieldCheck, TrendingUp, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { AiAnalysisPanel } from "./AiAnalysisPanel";
import { RelatedCves } from "./RelatedCves";
import { ReferenceList } from "./ReferenceList";
import { BookmarkButton } from "./BookmarkButton";
import { ShareButton } from "./ShareButton";
import { SeverityBadge } from "./SeverityBadge";
import { SourceBadgeCluster } from "./SourceBadgeCluster";
import { TicketControl } from "./TicketControl";
import { CommentThread } from "@/components/community/CommentThread";
import { formatDate } from "@/lib/utils";
import { decodeCvssVector } from "@/lib/cvss";
import { MarkdownLite } from "@/components/ui/markdown-lite";
import type { CpeMatch, Vulnerability } from "@/lib/types";

export function CveDetail({ vuln }: { vuln: Vulnerability }) {
  const decoded = decodeCvssVector(vuln.cvssVector);
  const metrics = vuln.enrichment?.metrics ?? [];
  const weaknesses = vuln.enrichment?.weaknesses ?? [];
  const richRefs = vuln.enrichment?.references ?? [];

  return (
    <article className="relative mx-auto max-w-7xl space-y-6 px-6 py-8">
      <Link
        href="/"
        aria-label="상세 닫기"
        className="absolute right-0 top-4 inline-flex h-9 w-9 items-center justify-center rounded-full border border-neutral-300 bg-white text-neutral-600 hover:border-neutral-500 hover:text-neutral-900 dark:border-neutral-800 dark:bg-surface-1 dark:text-neutral-400 dark:hover:border-neutral-600 dark:hover:text-neutral-100"
      >
        <X className="h-4 w-4" />
      </Link>

      <header className="space-y-3 pr-12">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-mono text-sm font-semibold text-neutral-500">{vuln.cveId}</span>
          <SeverityBadge severity={vuln.severity} score={vuln.cvssScore} />
          <SourceBadgeCluster sources={vuln.sources ?? [vuln.source]} size="md" />
          <BookmarkButton cveId={vuln.cveId} size="md" stopPropagation={false} />
          <ShareButton cveId={vuln.cveId} size="md" stopPropagation={false} />
          <span className="text-xs text-neutral-500">게시일: {formatDate(vuln.publishedAt)}</span>
          <span className="text-xs text-neutral-500">수정일: {formatDate(vuln.modifiedAt)}</span>
          {vuln.enrichment?.cna && (
            <span className="text-xs text-neutral-500">CNA: {vuln.enrichment.cna}</span>
          )}
          {vuln.enrichment?.vulnStatus && (
            <span className="rounded-full bg-surface-2 px-2 py-0.5 text-[10px] font-medium text-neutral-600 dark:text-neutral-400">
              {vuln.enrichment.vulnStatus}
            </span>
          )}
        </div>
        <h1 className="text-2xl font-bold leading-tight text-neutral-100">{vuln.title}</h1>
        {vuln.types.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {vuln.types.map((t) => (
              <Badge key={t} variant="secondary">
                {t}
              </Badge>
            ))}
          </div>
        )}
      </header>

      <ThreatSignals vuln={vuln} />

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">CVSS 벡터 · 메트릭</h2>
        </CardHeader>
        <CardContent className="space-y-3">
          {decoded.length > 0 && (
            <div className="grid gap-3 sm:grid-cols-2">
              {(["exploit", "impact"] as const).map((grp) => {
                const chips = decoded.filter((d) => d.group === grp);
                if (chips.length === 0) return null;
                return (
                  <div
                    key={grp}
                    className="rounded-xl border border-neutral-200 p-3.5 dark:border-neutral-800"
                  >
                    <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
                      {grp === "exploit" ? (
                        <Gauge className="h-3.5 w-3.5" />
                      ) : (
                        <ShieldCheck className="h-3.5 w-3.5" />
                      )}
                      {grp === "exploit" ? "악용 경로" : "영향"}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {chips.map((m) => (
                        <span
                          key={m.key}
                          title={m.label}
                          className="inline-flex items-center gap-1.5 rounded-full bg-surface-2 px-2.5 py-1 text-[11px]"
                        >
                          <span className="text-neutral-600 dark:text-neutral-400">{m.label}</span>
                          <span className={`font-semibold ${CHIP_TONE[m.tone]}`}>{m.value}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          {metrics.length > 0 && (
            <div className="rounded-xl border border-neutral-200 p-3.5 dark:border-neutral-800">
              <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
                <TrendingUp className="h-3.5 w-3.5" /> 버전별 점수
              </div>
              <div className="space-y-1">
                {metrics.map((m, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 text-[11px] text-neutral-500 dark:text-neutral-400">
                    <span className="rounded bg-neutral-200/70 px-1.5 py-0.5 font-mono dark:bg-surface-3">
                      CVSS {m.version}
                    </span>
                    {m.baseScore != null && (
                      <span className="font-semibold text-neutral-800 dark:text-neutral-200">{m.baseScore.toFixed(1)}</span>
                    )}
                    {m.baseSeverity && <span className="uppercase">{m.baseSeverity}</span>}
                    {m.exploitMaturity && <span>· 악용성숙도 {m.exploitMaturity}</span>}
                    {m.exploitabilityScore != null && <span>· 악용성 {m.exploitabilityScore}</span>}
                    {m.impactScore != null && <span>· 영향도 {m.impactScore}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
          {vuln.cvssVector ? (
            <code className="block break-all font-mono text-[11px] text-neutral-500">
              {vuln.cvssVector}
            </code>
          ) : (
            <p className="text-xs text-neutral-600">CVSS 벡터 정보 없음</p>
          )}
        </CardContent>
      </Card>

      {weaknesses.length > 0 && (
        <Card>
          <CardHeader>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
              약점 (CWE)
            </h2>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-wrap gap-2">
              {weaknesses.map((w) => (
                <li key={w.cweId}>
                  <a
                    href={w.url ?? `https://cwe.mitre.org/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-neutral-200 px-2.5 py-1 text-xs transition-colors hover:border-sky-400 dark:border-neutral-800 dark:hover:border-sky-500/50"
                  >
                    <span className="font-mono font-semibold text-neutral-800 dark:text-neutral-100">{w.cweId}</span>
                    {w.name && <span className="text-neutral-500 dark:text-neutral-400">{w.name}</span>}
                    <ExternalLink className="h-3 w-3 text-neutral-400" />
                  </a>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">상세 설명</h2>
        </CardHeader>
        <CardContent>
          {vuln.description ? (
            <MarkdownLite
              source={vuln.description}
              className="text-neutral-800 dark:text-neutral-300"
            />
          ) : (
            <p className="text-sm text-neutral-500">설명이 제공되지 않았습니다.</p>
          )}
        </CardContent>
      </Card>

      <AiAnalysisPanel cveId={vuln.cveId} />

      <RelatedCves cveId={vuln.cveId} />

      {vuln.affectedProducts.length > 0 && (
        <Card>
          <CardHeader>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
              영향받는 제품·버전
            </h2>
          </CardHeader>
          <CardContent>
            <ul className="divide-y divide-neutral-800">
              {vuln.affectedProducts.map((p, i) => (
                <li key={i} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <div>
                    <span className="font-medium text-neutral-100">
                      {p.vendor} {p.product}
                    </span>
                    {p.versionRange && (
                      <span className="ml-2 font-mono text-neutral-500">{p.versionRange}</span>
                    )}
                  </div>
                  <Badge variant="outline" className="uppercase">
                    {p.osFamily}
                  </Badge>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <CpeConfigSection matches={vuln.enrichment?.cpeMatches ?? []} />

      <ReferenceList cveId={vuln.cveId} richRefs={richRefs} fallbackRefs={vuln.references} />

      <TicketControl cveId={vuln.cveId} />

      <CommentThread vulnerabilityId={vuln.id} />

      <footer className="border-t border-neutral-800 pt-8">
        <p className="break-all text-xs text-neutral-500">
          출처:{" "}
          <a
            href={vuln.sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-neutral-300"
          >
            {vuln.sourceUrl}
          </a>
        </p>
      </footer>
    </article>
  );
}


// ─── 위협 신호 시각화 (CVSS · EPSS · KEV) ───────────────────────────
const SEV_BAR: Record<string, string> = {
  critical: "bg-rose-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-emerald-500",
};

const SEV_TEXT: Record<string, string> = {
  critical: "text-rose-600 dark:text-rose-400",
  high: "text-orange-600 dark:text-orange-400",
  medium: "text-amber-600 dark:text-amber-400",
  low: "text-emerald-600 dark:text-emerald-400",
};

// 칩 배경은 중립으로 통일하고 위험도 색은 *값(value)* 에만 입힌다 — 전부
// 분홍이던 기존안은 시끄럽고 라벨(opacity-70)이 흐려 가독성이 떨어졌다.
const CHIP_TONE: Record<string, string> = {
  high: "text-rose-700 dark:text-rose-300",
  med: "text-amber-700 dark:text-amber-300",
  low: "text-neutral-500 dark:text-neutral-400",
};

function Bar({ pct, className }: { pct: number; className: string }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
      <div
        className={`h-full rounded-full ${className}`}
        style={{ width: `${Math.max(0, Math.min(100, pct))}%` }}
      />
    </div>
  );
}

// 권고를 짧은 라벨 + 보조설명으로 분리해 컴팩트한 인라인 pill 로 렌더한다
// (기존 문장형 전체폭 배너는 너무 크고 장황했다).
function riskRead(vuln: Vulnerability): { label: string; hint: string; tone: string } {
  const score = typeof vuln.cvssScore === "number" ? vuln.cvssScore : 0;
  const epss = vuln.epssScore ?? null;
  if (vuln.kevListed)
    return {
      label: "즉시 패치",
      hint: "실측 악용 확인 · KEV 등재",
      tone: "border-rose-300 bg-rose-50 text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200",
    };
  if (epss != null && epss >= 0.5)
    return {
      label: "우선 조치",
      hint: `악용 확률 높음 · EPSS ${(epss * 100).toFixed(0)}%`,
      tone: "border-orange-300 bg-orange-50 text-orange-700 dark:border-orange-500/30 dark:bg-orange-500/10 dark:text-orange-200",
    };
  if (score >= 9)
    return {
      label: "시급 검토",
      hint: "이론 심각도 Critical",
      tone: "border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200",
    };
  if (epss != null && epss >= 0.1)
    return {
      label: "패치 계획",
      hint: "악용 가능성 중간",
      tone: "border-sky-300 bg-sky-50 text-sky-700 dark:border-sky-500/30 dark:bg-sky-500/10 dark:text-sky-200",
    };
  return {
    label: "정기 패치",
    hint: "높은 악용 신호 없음",
    tone: "border-neutral-200 bg-neutral-50 text-neutral-600 dark:border-neutral-800 dark:bg-surface-2 dark:text-neutral-400",
  };
}

function ThreatSignals({ vuln }: { vuln: Vulnerability }) {
  const score =
    typeof vuln.cvssScore === "number" && Number.isFinite(vuln.cvssScore) ? vuln.cvssScore : null;
  const sev = (vuln.severity ?? "").toLowerCase();
  const sevBar = SEV_BAR[sev] ?? "bg-neutral-400";
  const sevText = SEV_TEXT[sev] ?? "text-neutral-900 dark:text-neutral-100";
  const epss = vuln.epssScore ?? null; // 0..1 확률
  const pct = vuln.epssPercentile ?? null; // 0..1 백분위
  const kev = !!vuln.kevListed;
  const risk = riskRead(vuln);

  return (
    <Card>
      <CardHeader>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
          위협 신호 <span className="font-normal text-neutral-400">· CVSS · EPSS · KEV</span>
        </h2>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${risk.tone}`}>
          <span className="font-semibold">{risk.label}</span>
          <span className="opacity-75">· {risk.hint}</span>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          {/* CVSS — 이론 심각도 */}
          <div className="rounded-xl border border-neutral-200 p-3.5 dark:border-neutral-800">
            <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
              <Gauge className="h-3.5 w-3.5" /> CVSS
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-2xl font-bold ${sevText}`}>
                {score != null ? score.toFixed(1) : "—"}
              </span>
              <span className="text-xs uppercase text-neutral-500">{sev || "unknown"}</span>
            </div>
            <div className="mt-2">
              <Bar pct={score != null ? (score / 10) * 100 : 0} className={sevBar} />
            </div>
            <p className="mt-1.5 text-[10px] text-neutral-500">이론적 심각도 점수</p>
          </div>

          {/* EPSS — 악용 확률 예측 */}
          <div className="rounded-xl border border-neutral-200 p-3.5 dark:border-neutral-800">
            <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
              <TrendingUp className="h-3.5 w-3.5" /> EPSS
            </div>
            {epss != null ? (
              <>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-violet-600 dark:text-violet-400">
                    {(epss * 100).toFixed(1)}%
                  </span>
                  {pct != null && (
                    <span className="text-xs text-neutral-500">상위 {(100 - pct * 100).toFixed(1)}%</span>
                  )}
                </div>
                <div className="mt-2">
                  <Bar pct={epss * 100} className="bg-violet-500" />
                </div>
                <p className="mt-1.5 text-[10px] text-neutral-500">30일 내 악용 확률 예측</p>
              </>
            ) : (
              <>
                <span className="text-2xl font-bold text-neutral-300 dark:text-neutral-700">—</span>
                <p className="mt-1.5 text-[10px] text-neutral-500">예측 데이터 없음</p>
              </>
            )}
          </div>

          {/* KEV — 실측 악용 */}
          <div
            className={`rounded-xl border p-3.5 ${
              kev
                ? "border-rose-200 bg-rose-50/40 dark:border-rose-500/30 dark:bg-rose-500/5"
                : "border-neutral-200 dark:border-neutral-800"
            }`}
          >
            <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
              <Flame className={`h-3.5 w-3.5 ${kev ? "text-rose-500" : ""}`} /> KEV
            </div>
            {kev ? (
              <>
                <span className="inline-flex items-center gap-1 rounded-full bg-rose-100 px-2 py-0.5 text-sm font-semibold text-rose-800 dark:bg-rose-500/20 dark:text-rose-200">
                  <ShieldCheck className="h-3.5 w-3.5" /> 등재됨
                </span>
                <div className="mt-1.5 space-y-0.5">
                  {vuln.kevDateAdded && (
                    <p className="text-[10px] text-neutral-500">등재일 {formatDate(vuln.kevDateAdded)}</p>
                  )}
                  {vuln.kevDueDate && (
                    <p className="text-[10px] text-neutral-500">패치 기한 {formatDate(vuln.kevDueDate)}</p>
                  )}
                </div>
              </>
            ) : (
              <>
                <span className="text-lg font-semibold text-neutral-400 dark:text-neutral-500">미등재</span>
                <p className="mt-1.5 text-[10px] text-neutral-500">실측 악용 기록 없음</p>
              </>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── 영향받는 구성 (CPE) ────────────────────────────────────────────
function cpeLabel(c: string): string {
  const p = c.split(":");
  const pick = (i: number) => (p[i] && p[i] !== "*" && p[i] !== "-" ? p[i] : "");
  const s = [pick(3), pick(4), pick(5)].filter(Boolean).join(" ");
  return (s || c).replace(/\\/g, "");
}

function versionRange(m: CpeMatch): string {
  const parts: string[] = [];
  if (m.versionStartIncluding) parts.push(`≥ ${m.versionStartIncluding}`);
  if (m.versionStartExcluding) parts.push(`> ${m.versionStartExcluding}`);
  if (m.versionEndIncluding) parts.push(`≤ ${m.versionEndIncluding}`);
  if (m.versionEndExcluding) parts.push(`< ${m.versionEndExcluding}`);
  return parts.join("  ");
}

function CpeConfigSection({ matches }: { matches: CpeMatch[] }) {
  if (!matches.length) return null;
  return (
    <Card>
      <CardHeader>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
          영향받는 구성 (CPE){" "}
          <span className="font-normal text-neutral-400">{matches.length}</span>
        </h2>
      </CardHeader>
      <CardContent>
        <ul className="space-y-1.5">
          {matches.map((m, i) => {
            const range = versionRange(m);
            return (
              <li
                key={i}
                className="flex flex-wrap items-center gap-2 border-b border-neutral-100 pb-1.5 text-xs last:border-0 dark:border-neutral-800/60"
              >
                <span className="font-medium text-neutral-800 dark:text-neutral-200">
                  {cpeLabel(m.criteria)}
                </span>
                {range && (
                  <span className="rounded bg-amber-100 px-1.5 py-0.5 font-mono text-[10px] text-amber-800 dark:bg-amber-500/15 dark:text-amber-200">
                    {range}
                  </span>
                )}
                <span className="truncate font-mono text-[10px] text-neutral-400 dark:text-neutral-600">
                  {m.criteria}
                </span>
              </li>
            );
          })}
        </ul>
      </CardContent>
    </Card>
  );
}
