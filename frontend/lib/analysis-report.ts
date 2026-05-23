// Build a downloadable Markdown report from a CVE analysis + Q&A
// thread. The output is meant for both copy/paste into a ticket and
// archival on disk, so we keep headings shallow (## for sections) and
// use fenced code blocks for payloads.

import type { AiAnalysisResponse } from "./api";
import type { QaTurn } from "./analysis-qa";

function header(meta: { cveId: string; timestamp: number }): string {
  const when = new Date(meta.timestamp).toISOString().replace("T", " ").slice(0, 19);
  return [
    `# ${meta.cveId} — Kestrel AI 분석 리포트`,
    "",
    `_생성 시각: ${when} UTC_`,
    "",
    "---",
    "",
  ].join("\n");
}

function payloadsSection(result: AiAnalysisResponse): string {
  if (!result.payloadExamples.length) return "";
  const blocks = result.payloadExamples.map(
    (p, i) => `### #${i + 1}\n\n\`\`\`\n${p}\n\`\`\``,
  );
  return `## 예시 페이로드 (${result.payloadExamples.length}종)\n\n${blocks.join("\n\n")}\n\n`;
}

function mitigationsSection(result: AiAnalysisResponse): string {
  if (!result.mitigations.length) return "";
  const lines = result.mitigations.map((m, i) => `${i + 1}. ${m}`);
  return `## 패치 / 대응 항목 (${result.mitigations.length}개)\n\n${lines.join("\n")}\n\n`;
}

function qaSection(turns: QaTurn[]): string {
  if (!turns.length) return "";
  const blocks = turns.map((t, i) => {
    const when = new Date(t.timestamp).toISOString().replace("T", " ").slice(0, 19);
    return [
      `### Q${i + 1}. ${t.question}`,
      `_${when} UTC_`,
      "",
      t.answer,
    ].join("\n");
  });
  return `## 추가 Q&A\n\n${blocks.join("\n\n---\n\n")}\n\n`;
}

export function buildAnalysisMarkdown(args: {
  cveId: string;
  title?: string;
  result: AiAnalysisResponse;
  qa: QaTurn[];
  generatedAt?: number;
}): string {
  const parts: string[] = [];
  parts.push(header({ cveId: args.cveId, timestamp: args.generatedAt ?? Date.now() }));
  if (args.title) {
    parts.push(`**제목**: ${args.title}\n`);
  }
  parts.push(`## 공격 기법\n\n${args.result.attackMethod}\n`);
  parts.push(payloadsSection(args.result));
  parts.push(mitigationsSection(args.result));
  parts.push(qaSection(args.qa));
  parts.push(
    "---\n\n_본 리포트는 Kestrel AI 심층 분석 결과입니다. 참고용이며, 실제 대응 전에는 반드시 전문가 검토가 필요합니다._\n",
  );
  return parts.filter(Boolean).join("\n");
}

export function downloadAnalysisMarkdown(args: {
  cveId: string;
  title?: string;
  result: AiAnalysisResponse;
  qa: QaTurn[];
}): void {
  if (typeof window === "undefined") return;
  const md = buildAnalysisMarkdown(args);
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safeId = args.cveId.replace(/[^A-Za-z0-9-_]/g, "_");
  const stamp = new Date().toISOString().slice(0, 10);
  a.download = `${safeId}-analysis-${stamp}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
