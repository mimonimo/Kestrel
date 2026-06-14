"use client";

/**
 * Markdown 렌더러 — Kestrel AI 분석·커뮤니티 글·댓글·공지 공용.
 *
 * 표준 파서(react-markdown + remark-gfm)를 사용해 CommonMark/GFM 규칙대로 정확히
 * 렌더한다. 과거의 직접 파서가 의존하던 "깨진 마크업 강제 정리"(고아 마커 삭제,
 * 줄바꿈 강제 병합) 휴리스틱을 제거 — 외부(BYOA) 에이전트가 내놓는 마크다운도
 * 규칙대로 처리된다. ``remark-breaks`` 로 단락 내 단일 줄바꿈을 그대로(<br>) 보존해
 * 사용자가 입력한 줄바꿈이 임의로 합쳐지지 않는다.
 *
 * Kestrel 고유 렌더링은 커스텀 컴포넌트/플러그인으로 보존한다:
 *  - ``## 제목`` → 섹션 카드(아이콘·색상). compact 모드(댓글 등)에서는 소제목.
 *  - 코드블록 → 언어 라벨·줄번호·복사·경량 하이라이트.
 *  - ``CVE-XXXX`` → 해당 취약점 상세로 자동 링크(원문 텍스트는 건드리지 않음).
 *  - raw HTML 은 렌더하지 않는다(rehype-raw 미사용) → XSS 차단.
 */
import { type ReactNode, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import type { Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkBreaks from "remark-breaks";
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

// ─── CVE 자동 링크 remark 플러그인 ───────────────────────
// mdast 의 text 노드만 분할해 CVE-XXXX 를 내부 링크 노드로 치환한다.
// 코드(inlineCode/code)·기존 링크 안은 건드리지 않는다(중첩 링크 방지).
const CVE_TEST = /\bCVE-\d{4}-\d{4,7}\b/;
const CVE_SPLIT = /\bCVE-\d{4}-\d{4,7}\b/g;

interface MdNode {
  type: string;
  value?: string;
  url?: string;
  children?: MdNode[];
  data?: Record<string, unknown>;
}

function remarkCveLinks() {
  const walk = (node: MdNode) => {
    if (!node.children) return;
    if (node.type === "link" || node.type === "linkReference") return;
    const next: MdNode[] = [];
    for (const child of node.children) {
      if (child.type === "text" && child.value && CVE_TEST.test(child.value)) {
        const val = child.value;
        let last = 0;
        let m: RegExpExecArray | null;
        CVE_SPLIT.lastIndex = 0;
        while ((m = CVE_SPLIT.exec(val)) !== null) {
          if (m.index > last) next.push({ type: "text", value: val.slice(last, m.index) });
          next.push({
            type: "link",
            url: `/cve/${m[0]}`,
            children: [{ type: "text", value: m[0] }],
            data: { hProperties: { className: "cve-link" } },
          });
          last = m.index + m[0].length;
        }
        if (last < val.length) next.push({ type: "text", value: val.slice(last) });
      } else {
        walk(child);
        next.push(child);
      }
    }
    node.children = next;
  };
  return (tree: MdNode) => walk(tree);
}

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
    <div className="my-2 overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-surface-2">
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
      headerCls:
        "border-emerald-200 bg-emerald-50/70 dark:border-emerald-500/20 dark:bg-emerald-500/5",
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

// ─── react-markdown 컴포넌트 매핑 ────────────────────────
const COMPONENTS: Components = {
  // 펜스 코드블록(<pre><code>)은 pre 를 풀고 code 가 CodeBlock 을 그린다
  // (div 를 pre 안에 넣으면 안 되므로).
  pre: ({ children }) => <>{children}</>,
  code({ className, children }) {
    const text = String(children ?? "");
    const isBlock = /language-/.test(className || "") || text.includes("\n");
    if (isBlock) return <CodeBlock code={text.replace(/\n$/, "")} />;
    return (
      <code className="rounded bg-neutral-200/70 px-1 py-0.5 font-mono text-[0.85em] text-violet-700 dark:bg-surface-3 dark:text-violet-300">
        {children}
      </code>
    );
  },
  a({ href, children }) {
    const url = href || "#";
    const internal = url.startsWith("/");
    return (
      <a
        href={url}
        {...(internal ? {} : { target: "_blank", rel: "noopener noreferrer" })}
        className="font-medium text-sky-600 hover:underline dark:text-sky-400"
      >
        {children}
      </a>
    );
  },
  p: ({ children }) => (
    <p className="leading-relaxed text-neutral-800 dark:text-neutral-200">{children}</p>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-neutral-900 dark:text-neutral-100">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="italic text-neutral-800 dark:text-neutral-200">{children}</em>
  ),
  del: ({ children }) => (
    <del className="text-neutral-500 dark:text-neutral-500">{children}</del>
  ),
  h1: ({ children }) => (
    <h2 className="text-base font-bold text-neutral-900 dark:text-neutral-100">{children}</h2>
  ),
  h2: ({ children }) => (
    <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">{children}</h3>
  ),
  h3: ({ children }) => (
    <h4 className="font-semibold text-neutral-800 dark:text-neutral-200">{children}</h4>
  ),
  h4: ({ children }) => (
    <h5 className="font-semibold text-neutral-800 dark:text-neutral-200">{children}</h5>
  ),
  h5: ({ children }) => (
    <h6 className="font-semibold text-neutral-700 dark:text-neutral-300">{children}</h6>
  ),
  h6: ({ children }) => (
    <h6 className="font-semibold text-neutral-700 dark:text-neutral-300">{children}</h6>
  ),
  ul: ({ children }) => (
    <ul className="ml-5 list-disc space-y-1.5 leading-relaxed marker:text-neutral-400 dark:marker:text-neutral-500">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="ml-5 list-decimal space-y-1.5 leading-relaxed marker:text-neutral-400 dark:marker:text-neutral-500">
      {children}
    </ol>
  ),
  li: ({ children }) => <li className="pl-1">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-neutral-300 pl-3 text-neutral-600 dark:border-neutral-700 dark:text-neutral-400">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="border-neutral-200 dark:border-neutral-800" />,
  table: ({ children }) => (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th className="border border-neutral-200 bg-neutral-50 px-2 py-1 text-left font-semibold dark:border-neutral-800 dark:bg-surface-2">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="border border-neutral-200 px-2 py-1 dark:border-neutral-800">{children}</td>
  ),
};

const REMARK_PLUGINS = [remarkGfm, remarkBreaks, remarkCveLinks];
const REMARK_PLUGINS_INLINE = [remarkGfm, remarkCveLinks];

function Md({ children }: { children: string }) {
  return (
    <div className="space-y-3 text-sm">
      <ReactMarkdown remarkPlugins={REMARK_PLUGINS} components={COMPONENTS}>
        {children}
      </ReactMarkdown>
    </div>
  );
}

// 섹션 제목 등 인라인 전용 — 블록 <p> 래핑 없이 한 줄로.
function InlineMd({ children }: { children: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={REMARK_PLUGINS_INLINE}
      components={{ ...COMPONENTS, p: ({ children: c }) => <>{c}</> }}
    >
      {children}
    </ReactMarkdown>
  );
}

function SectionCard({ title, body }: { title: string; body: string }) {
  const { icon: Icon, headerCls, iconCls } = sectionMeta(title);
  return (
    <section className="overflow-hidden rounded-xl border border-neutral-200 dark:border-neutral-800">
      <div className={cn("flex items-center gap-2 border-b px-4 py-2.5", headerCls)}>
        <Icon className={cn("h-4 w-4 shrink-0", iconCls)} />
        <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
          <InlineMd>{title}</InlineMd>
        </h3>
      </div>
      <div className="px-4 py-3.5 text-sm">
        <Md>{body}</Md>
      </div>
    </section>
  );
}

// ─── 본문: ``## 제목`` 기준으로 섹션 카드 분할(코드펜스 안의 ## 은 무시) ──
interface Part {
  title: string | null; // null = 카드 없는 프리앰블
  body: string;
}

function splitSections(source: string): Part[] {
  const lines = source.split("\n");
  const parts: Part[] = [{ title: null, body: "" }];
  const cur = () => parts[parts.length - 1];
  let inFence = false;
  for (const line of lines) {
    if (/^\s*(```+|~~~+)/.test(line)) inFence = !inFence;
    const h2 = !inFence && /^##\s+(.*)$/.exec(line);
    if (h2) {
      parts.push({ title: h2[1].replace(/\s*#+\s*$/, "").trim(), body: "" });
    } else {
      cur().body += (cur().body ? "\n" : "") + line;
    }
  }
  return parts;
}

export function MarkdownLite({
  source,
  className,
  compact = false,
}: {
  source: string;
  className?: string;
  /** 댓글 등 좁은 영역용 — ``##`` 를 섹션 카드 대신 소제목으로 렌더. */
  compact?: boolean;
}) {
  const src = (source ?? "").replace(/\r\n/g, "\n");

  if (compact) {
    return (
      <div className={className}>
        <Md>{src}</Md>
      </div>
    );
  }

  const parts = splitSections(src);
  return (
    <div className={cn("space-y-4", className)}>
      {parts.map((p, i) =>
        p.title === null ? (
          p.body.trim() ? <Md key={i}>{p.body}</Md> : null
        ) : (
          <SectionCard key={i} title={p.title} body={p.body} />
        ),
      )}
    </div>
  );
}
