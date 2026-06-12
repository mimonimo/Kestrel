"use client";

/**
 * 경량 Markdown 렌더러 — Kestrel AI 분석 본문(result_md)용. 외부 의존성 없음.
 *
 * 처리: ## 섹션(카드+아이콘·색상), ### 소제목, **bold**, `code`(삼중/이중 포함),
 * _italic_, 펜스/한 줄 코드블록(언어 라벨·줄번호·복사·경량 하이라이트),
 * 1. 순서목록, - 불릿, --- 구분선, 문단.
 */
import { type ReactNode, useMemo, useState } from "react";
import {
  Check,
  Code2,
  Copy,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";

// 인라인: 코드 → **굵게**/__굵게__ → _기울임_ → 고아 마커 정리.
// 단일 ``*`` 는 ``/api/*`` · 정규식 ``.*`` 등 보안 텍스트에서 흔해 절대 건드리지
// 않는다. 모델이 종종 토해내는 깨진 마크업(``**_x_**`` 중첩, 닫히지 않은
// ``**`` / 끝에 매달린 ``_``)을 안전하게 정리해 ``###`` · ``**`` · ``_`` 가
// 본문에 글자 그대로 노출되지 않게 한다.

function stripCode(tok: string): string {
  if (tok.startsWith("```")) return tok.slice(3, -3);
  if (tok.startsWith("``")) return tok.slice(2, -2);
  return tok.slice(1, -1);
}

// 짝이 맞지 않아 남은 강조 마커 제거. ``**`` 런과 *단어 경계가 아닌* ``_`` 만
// 지운다(식별자 TARGET_HOST 의 ``_`` 는 보존).
function cleanMarkers(s: string): string {
  let out = s.replace(/\*\*+/g, "");
  out = out.replace(/_+/g, (m, off: number) => {
    const before = out[off - 1] || "";
    const after = out[off + m.length] || "";
    const intraword = /[A-Za-z0-9]/.test(before) && /[A-Za-z0-9]/.test(after);
    return intraword ? m : "";
  });
  return out;
}

function renderInline(text: string): ReactNode[] {
  let k = 0;
  const nextKey = () => `il-${k++}`;
  const leaf = (s: string): ReactNode[] => {
    const c = cleanMarkers(s);
    return c ? [c] : [];
  };

  const italic = (t: string): ReactNode[] => {
    const re = /(?<![A-Za-z0-9])_(?!\s)([^_]+?)(?<!\s)_(?![A-Za-z0-9])/g;
    const out: ReactNode[] = [];
    let last = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(t)) !== null) {
      if (m.index > last) out.push(...leaf(t.slice(last, m.index)));
      out.push(
        <em key={nextKey()} className="italic text-neutral-800 dark:text-neutral-200">
          {cleanMarkers(m[1])}
        </em>,
      );
      last = m.index + m[0].length;
    }
    if (last < t.length) out.push(...leaf(t.slice(last)));
    return out;
  };

  const bold = (t: string): ReactNode[] => {
    const re = /\*\*([\s\S]+?)\*\*|(?<![A-Za-z0-9])__([\s\S]+?)__(?![A-Za-z0-9])/g;
    const out: ReactNode[] = [];
    let last = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(t)) !== null) {
      if (m.index > last) out.push(...italic(t.slice(last, m.index)));
      out.push(
        <strong key={nextKey()} className="font-semibold text-neutral-900 dark:text-neutral-100">
          {italic(m[1] ?? m[2] ?? "")}
        </strong>,
      );
      last = m.index + m[0].length;
    }
    if (last < t.length) out.push(...italic(t.slice(last)));
    return out;
  };

  const code = (t: string): ReactNode[] => {
    const re = /```[^`]+```|``[^`]+``|`[^`]+`/g;
    const out: ReactNode[] = [];
    let last = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(t)) !== null) {
      if (m.index > last) out.push(...bold(t.slice(last, m.index)));
      const raw = stripCode(m[0]);
      out.push(
        raw.includes("\n") ? (
          // 줄바꿈이 든 인라인 코드(모델이 백틱 안에 멀티라인 패치를 넣는 경우)
          // 는 한 줄로 뭉개지지 않게 블록(pre-wrap)으로 렌더한다.
          <code
            key={nextKey()}
            className="my-1 block overflow-x-auto whitespace-pre-wrap rounded-md bg-neutral-100 p-2 font-mono text-[0.8em] leading-relaxed text-neutral-800 dark:bg-surface-3 dark:text-neutral-100"
          >
            {raw}
          </code>
        ) : (
          <code
            key={nextKey()}
            className="rounded bg-neutral-200/70 px-1 py-0.5 font-mono text-[0.85em] text-violet-700 dark:bg-surface-3 dark:text-violet-300"
          >
            {raw}
          </code>
        ),
      );
      last = m.index + m[0].length;
    }
    if (last < t.length) out.push(...bold(t.slice(last)));
    return out;
  };

  return code(text);
}

const FULL_CODE = /^\s*(```|``|`)([\s\S]+?)\1\s*$/;

// ─── 코드블록(언어 라벨 + 줄번호 + 복사 + 경량 하이라이트) ──
function detectLanguage(source: string): string {
  const s = source.trim();
  if (/^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\//m.test(s)) return "http";
  if (/^\s*curl\b/m.test(s)) return "bash";
  if (/\b(?:SELECT|UNION|INSERT|UPDATE|DROP)\b/i.test(s) && /\b(?:FROM|WHERE|TABLE|OR)\b/i.test(s))
    return "sql";
  if (/<script|onerror=|onload=|javascript:|alert\(/i.test(s)) return "xss";
  if (/^\s*(?:id|name):/m.test(s) && /\bmatchers\b|\brequests\b/.test(s)) return "nuclei";
  if (/^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\()/m.test(s)) return "python";
  if (/[#$]\s*\w+|(?:^|\n)(?:\$|#)\s/m.test(s) || /\|\s*sh\b/.test(s)) return "bash";
  return "text";
}

// 안전한 토큰 하이라이트 — 문자열/숫자/주요 키워드만(오탐 최소화).
const TOKEN =
  /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b\d+(?:\.\d+)?\b|\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP|SELECT|UNION|INSERT|UPDATE|DROP|FROM|WHERE|TABLE|OR|AND|NULL|script|alert|onerror|onload|eval|prompt|import|from|def|function|return|var|let|const|sudo|curl|wget|bash|nc|echo|cat)\b)/gi;

function highlightLine(line: string): ReactNode[] {
  if (!line) return [" "];
  const out: ReactNode[] = [];
  let last = 0;
  let key = 0;
  let m: RegExpExecArray | null;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(line)) !== null) {
    if (m.index > last) out.push(line.slice(last, m.index));
    const tok = m[0];
    const c = tok[0];
    const cls =
      c === '"' || c === "'"
        ? "text-emerald-600 dark:text-emerald-400"
        : /^\d/.test(tok)
          ? "text-amber-600 dark:text-amber-400"
          : "text-violet-600 dark:text-violet-300";
    out.push(
      <span key={key++} className={cls}>
        {tok}
      </span>,
    );
    last = m.index + tok.length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const lang = useMemo(() => detectLanguage(code), [code]);
  const lines = useMemo(() => code.replace(/\n$/, "").split("\n"), [code]);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* 무시 */
    }
  };
  return (
    <div className="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-surface-2">
      <div className="flex items-center justify-between border-b border-neutral-200 bg-white px-3 py-1.5 dark:border-neutral-800 dark:bg-surface-3">
        <span className="font-mono text-[10px] uppercase tracking-wider text-neutral-600 dark:text-neutral-400">
          {lang}
        </span>
        <button
          type="button"
          onClick={onCopy}
          aria-label="코드 복사"
          className={cn(
            "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium transition-colors",
            copied
              ? "text-emerald-600 dark:text-emerald-400"
              : "text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100",
          )}
        >
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? "복사됨" : "복사"}
        </button>
      </div>
      <pre className="overflow-x-auto py-3 text-xs leading-relaxed">
        <code className="block font-mono">
          {lines.map((line, i) => (
            <div key={i} className="flex items-start">
              <span className="sticky left-0 shrink-0 select-none bg-neutral-50 px-3 pt-0.5 text-right font-mono text-[10px] text-neutral-500 dark:bg-surface-2 dark:text-neutral-600">
                {String(i + 1).padStart(2, " ")}
              </span>
              <span className="min-w-0 flex-1 whitespace-pre-wrap break-all pr-4 text-neutral-800 dark:text-neutral-100">
                {/^\s*#/.test(line) ? (
                  <span className="text-neutral-500 dark:text-neutral-500">{line}</span>
                ) : (
                  highlightLine(line)
                )}
              </span>
            </div>
          ))}
        </code>
      </pre>
    </div>
  );
}

// ─── 섹션 카드(제목별 아이콘·색상) ───────────────────────
interface SectionMeta {
  icon: typeof ShieldAlert;
  headerCls: string;
  iconCls: string;
}
function sectionMeta(title: string): SectionMeta {
  const t = title.toLowerCase();
  if (/공격|기법|attack|벡터|exploit|익스플로/.test(t))
    return {
      icon: ShieldAlert,
      headerCls: "border-rose-200 bg-rose-50/70 dark:border-rose-500/20 dark:bg-rose-500/5",
      iconCls: "text-rose-600 dark:text-rose-400",
    };
  if (/페이로드|payload|예시|poc|샘플/.test(t))
    return {
      icon: Code2,
      headerCls: "border-sky-200 bg-sky-50/70 dark:border-sky-500/20 dark:bg-sky-500/5",
      iconCls: "text-sky-600 dark:text-sky-400",
    };
  if (/완화|대응|패치|방어|조치|mitigat|remediat|fix|patch/.test(t))
    return {
      icon: ShieldCheck,
      headerCls: "border-emerald-200 bg-emerald-50/70 dark:border-emerald-500/20 dark:bg-emerald-500/5",
      iconCls: "text-emerald-600 dark:text-emerald-400",
    };
  if (/q&a|질문|문의|추가|faq/.test(t))
    return {
      icon: HelpCircle,
      headerCls: "border-violet-200 bg-violet-50/70 dark:border-violet-500/20 dark:bg-violet-500/5",
      iconCls: "text-violet-600 dark:text-violet-400",
    };
  return {
    icon: Sparkles,
    headerCls: "border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-surface-2",
    iconCls: "text-violet-600 dark:text-violet-400",
  };
}

function SectionCard({ title, children }: { title: string; children: ReactNode }) {
  const { icon: Icon, headerCls, iconCls } = sectionMeta(title);
  return (
    <section className="overflow-hidden rounded-xl border border-neutral-200 dark:border-neutral-800">
      <div className={cn("flex items-center gap-2 border-b px-4 py-2.5", headerCls)}>
        <Icon className={cn("h-4 w-4 shrink-0", iconCls)} />
        <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
          {renderInline(title)}
        </h3>
      </div>
      <div className="space-y-3 px-4 py-3.5 text-sm">{children}</div>
    </section>
  );
}

// ─── 본문 파서 ───────────────────────────────────────────
interface Section {
  title: string | null; // null = 카드 없는 프리앰블
  blocks: ReactNode[];
}

export function MarkdownLite({ source, className }: { source: string; className?: string }) {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const sections: Section[] = [{ title: null, blocks: [] }];
  let para: string[] = [];
  let key = 0;
  const cur = () => sections[sections.length - 1];

  const flushPara = () => {
    if (para.length === 0) return;
    cur().blocks.push(
      <p key={key++} className="leading-relaxed text-neutral-800 dark:text-neutral-200">
        {renderInline(para.join(" "))}
      </p>,
    );
    para = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // 코드 펜스 — 불릿 접두사(- ```)·여는 줄 같은 줄 내용·줄 끝 닫힘까지 처리.
    const fence = /^\s*(?:[-*]\s+)?(```+)(.*)$/.exec(line);
    if (fence) {
      flushPara();
      const buf: string[] = [];
      const firstRest = fence[2];
      let closed = false;
      if (firstRest) {
        const ci = firstRest.indexOf("```");
        if (ci !== -1) {
          buf.push(firstRest.slice(0, ci));
          closed = true;
        } else {
          buf.push(firstRest);
        }
      }
      if (!closed) {
        i++;
        while (i < lines.length) {
          const l = lines[i];
          const ci = l.indexOf("```");
          if (ci !== -1) {
            const before = l.slice(0, ci);
            if (before.trim()) buf.push(before);
            closed = true;
            break;
          }
          buf.push(l);
          i++;
        }
      }
      const code = buf.join("\n").replace(/^\n+|\n+$/g, "");
      cur().blocks.push(<CodeBlock key={key++} code={code} />);
      continue;
    }

    if (/^---+\s*$/.test(line)) {
      flushPara();
      cur().blocks.push(<hr key={key++} className="border-neutral-200 dark:border-neutral-800" />);
      continue;
    }

    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      flushPara();
      const level = h[1].length;
      const text = h[2].replace(/\s*#+\s*$/, ""); // 끝에 매달린 ATX 닫는 # 제거
      if (level === 2) {
        // 새 섹션 카드 시작.
        sections.push({ title: text, blocks: [] });
      } else if (level === 1) {
        cur().blocks.push(
          <h2 key={key++} className="text-base font-bold text-neutral-900 dark:text-neutral-100">
            {renderInline(text)}
          </h2>,
        );
      } else {
        cur().blocks.push(
          <h4 key={key++} className="font-semibold text-neutral-800 dark:text-neutral-200">
            {renderInline(text)}
          </h4>,
        );
      }
      continue;
    }

    if (/^\s*\d+\.\s+/.test(line)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length) {
        const l = lines[i];
        if (/^\s*\d+\.\s+/.test(l)) {
          items.push(l.replace(/^\s*\d+\.\s+/, ""));
          i++;
        } else if (
          items.length > 0 &&
          l.trim() !== "" &&
          !/^\s*[-*]\s+/.test(l) &&
          !/^#{1,6}\s+/.test(l) &&
          !/^---+\s*$/.test(l) &&
          !/^\s*```+/.test(l)
        ) {
          items[items.length - 1] += "\n" + l;
          i++;
        } else {
          break;
        }
      }
      i--;
      cur().blocks.push(
        <ol
          key={key++}
          className="list-decimal space-y-1.5 pl-5 text-neutral-800 marker:text-neutral-400 dark:text-neutral-200 dark:marker:text-neutral-500"
        >
          {items.map((it, j) => (
            <li key={j} className="leading-relaxed">
              {renderInline(it)}
            </li>
          ))}
        </ol>,
      );
      continue;
    }

    if (/^\s*[-*]\s+/.test(line)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length) {
        const l = lines[i];
        if (/^\s*[-*]\s+/.test(l)) {
          items.push(l.replace(/^\s*[-*]\s+/, ""));
          i++;
        } else if (
          items.length > 0 &&
          l.trim() !== "" &&
          !/^\s*\d+\.\s+/.test(l) &&
          !/^#{1,6}\s+/.test(l) &&
          !/^---+\s*$/.test(l) &&
          !/^\s*```+/.test(l)
        ) {
          // 이전 항목이 이어지는 줄(백틱 안 멀티라인 코드 등으로 줄바꿈된 경우)
          // — 줄 단위로 끊지 말고 합친다.
          items[items.length - 1] += "\n" + l;
          i++;
        } else {
          break;
        }
      }
      i--;
      cur().blocks.push(
        <ul key={key++} className="space-y-1.5 text-neutral-800 dark:text-neutral-200">
          {items.map((it, j) => {
            const fc = FULL_CODE.exec(it);
            if (fc) {
              return (
                <li key={j} className="list-none">
                  <CodeBlock code={fc[2]} />
                </li>
              );
            }
            return (
              <li
                key={j}
                className="ml-5 list-disc leading-relaxed marker:text-neutral-400 dark:marker:text-neutral-500"
              >
                {renderInline(it)}
              </li>
            );
          })}
        </ul>,
      );
      continue;
    }

    if (line.trim() === "") {
      flushPara();
      continue;
    }

    para.push(line.trim());
  }
  flushPara();

  return (
    <div className={cn("space-y-4", className)}>
      {sections.map((s, i) =>
        s.title === null ? (
          s.blocks.length ? (
            <div key={i} className="space-y-3 text-sm">
              {s.blocks}
            </div>
          ) : null
        ) : (
          <SectionCard key={i} title={s.title}>
            {s.blocks}
          </SectionCard>
        ),
      )}
    </div>
  );
}
