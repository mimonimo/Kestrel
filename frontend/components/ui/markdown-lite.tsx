"use client";

/**
 * 경량 Markdown 렌더러 — Kestrel AI 분석 리포트(`buildAnalysisMarkdown`)가
 * 만드는 서브셋만 처리한다: #/##/### 헤딩, **bold**, `code`, _italic_,
 * 펜스 코드블록(```), 1. 순서목록, - 불릿, --- 구분선, 문단.
 * 외부 의존성 없이(번들·빌드 가벼움) 서버 친화적.
 */
import { type ReactNode, useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/utils";

const INLINE = /(```[^`]+```|``[^`]+``|`[^`]+`|\*\*[^*]+\*\*|_[^_]+_)/g;

function stripCode(tok: string): string {
  if (tok.startsWith("```")) return tok.slice(3, -3);
  if (tok.startsWith("``")) return tok.slice(2, -2);
  return tok.slice(1, -1);
}

function renderInline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  let key = 0;
  let m: RegExpExecArray | null;
  INLINE.lastIndex = 0;
  while ((m = INLINE.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) {
      nodes.push(
        <code
          key={key++}
          className="rounded bg-neutral-200/70 px-1 py-0.5 font-mono text-[0.85em] text-violet-700 dark:bg-surface-3 dark:text-violet-300"
        >
          {stripCode(tok)}
        </code>,
      );
    } else if (tok.startsWith("**")) {
      nodes.push(
        <strong key={key++} className="font-semibold text-neutral-900 dark:text-neutral-100">
          {tok.slice(2, -2)}
        </strong>,
      );
    } else {
      nodes.push(
        <em key={key++} className="text-neutral-600 dark:text-neutral-400">
          {tok.slice(1, -1)}
        </em>,
      );
    }
    last = m.index + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

// 한 줄 전체가 코드로 감싸진 항목인지 (예: 저장된 페이로드 "```payload```").
const FULL_CODE = /^\s*(```|``|`)([\s\S]+?)\1\s*$/;

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
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
    <div className="group relative">
      <button
        type="button"
        onClick={onCopy}
        aria-label="코드 복사"
        className={cn(
          "absolute right-2 top-2 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium transition-colors",
          copied
            ? "text-emerald-600 dark:text-emerald-400"
            : "text-neutral-500 opacity-0 hover:text-neutral-800 group-hover:opacity-100 dark:hover:text-neutral-100",
        )}
      >
        {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
        {copied ? "복사됨" : "복사"}
      </button>
      <pre className="overflow-x-auto rounded-lg border border-neutral-200 bg-neutral-50 p-3 text-[12px] leading-relaxed dark:border-neutral-800 dark:bg-surface-2">
        <code className="font-mono text-neutral-800 dark:text-neutral-200">{code}</code>
      </pre>
    </div>
  );
}

export function MarkdownLite({ source, className }: { source: string; className?: string }) {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let para: string[] = [];
  let key = 0;

  const flushPara = () => {
    if (para.length === 0) return;
    blocks.push(
      <p key={key++} className="leading-relaxed text-neutral-800 dark:text-neutral-200">
        {renderInline(para.join(" "))}
      </p>,
    );
    para = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // 펜스 코드블록
    if (line.trimStart().startsWith("```")) {
      flushPara();
      const buf: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) {
        buf.push(lines[i]);
        i++;
      }
      blocks.push(<CodeBlock key={key++} code={buf.join("\n")} />);
      continue;
    }

    // 구분선
    if (/^---+\s*$/.test(line)) {
      flushPara();
      blocks.push(<hr key={key++} className="border-neutral-200 dark:border-neutral-800" />);
      continue;
    }

    // 헤딩
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) {
      flushPara();
      const level = h[1].length;
      const text = h[2];
      if (level === 1) {
        blocks.push(
          <h2 key={key++} className="text-base font-bold text-neutral-900 dark:text-neutral-100">
            {renderInline(text)}
          </h2>,
        );
      } else if (level === 2) {
        blocks.push(
          <h3
            key={key++}
            className="mt-1 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-violet-700 dark:text-violet-300"
          >
            {renderInline(text)}
          </h3>,
        );
      } else {
        blocks.push(
          <h4 key={key++} className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">
            {renderInline(text)}
          </h4>,
        );
      }
      continue;
    }

    // 순서 목록 (연속 수집)
    if (/^\s*\d+\.\s+/.test(line)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ""));
        i++;
      }
      i--;
      blocks.push(
        <ol key={key++} className="list-decimal space-y-1.5 pl-5 text-neutral-800 marker:text-neutral-400 dark:text-neutral-200 dark:marker:text-neutral-500">
          {items.map((it, j) => (
            <li key={j} className="leading-relaxed">
              {renderInline(it)}
            </li>
          ))}
        </ol>,
      );
      continue;
    }

    // 불릿 목록
    if (/^\s*[-*]\s+/.test(line)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, ""));
        i++;
      }
      i--;
      blocks.push(
        <ul key={key++} className="space-y-1.5 text-neutral-800 dark:text-neutral-200">
          {items.map((it, j) => {
            const fc = FULL_CODE.exec(it);
            // 페이로드처럼 항목 전체가 코드로 감싸진 경우 → 코드블록.
            if (fc) {
              return (
                <li key={j} className="list-none">
                  <CodeBlock code={fc[2]} />
                </li>
              );
            }
            return (
              <li key={j} className="ml-5 list-disc leading-relaxed marker:text-neutral-400 dark:marker:text-neutral-500">
                {renderInline(it)}
              </li>
            );
          })}
        </ul>,
      );
      continue;
    }

    // 빈 줄 → 문단 분리
    if (line.trim() === "") {
      flushPara();
      continue;
    }

    para.push(line.trim());
  }
  flushPara();

  return <div className={cn("space-y-3 text-sm", className)}>{blocks}</div>;
}
