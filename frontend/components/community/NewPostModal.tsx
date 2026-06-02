"use client";

/**
 * 새 글 작성 모달 (PR 10-CW — UI 개선).
 *
 * 개선:
 *  - light/dark parity (이전엔 다크 톤만)
 *  - backdrop blur + animate-in 진입
 *  - title / body 글자수 카운터
 *  - 작성자 메타를 헤더 좌상단 배지로
 *  - CVE 연결 표시는 헤더 우측 칩으로
 *  - 키보드 단축키: Esc 닫기 / Cmd+Enter 게시
 *  - body scroll lock + ESC 외부클릭 닫기
 */
import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Hash, Loader2, Send, User as UserIcon, X } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

interface Props {
  open: boolean;
  onClose: () => void;
  vulnerabilityId?: string;
}

const TITLE_MAX = 255;
const BODY_MAX = 20000;

export function NewPostModal({ open, onClose, vulnerabilityId }: Props) {
  const qc = useQueryClient();
  const { user } = useAuth();
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);
  const titleRef = useRef<HTMLInputElement>(null);

  const displayName = (user?.nickname || user?.username || "").trim();
  const initial = displayName.trim().charAt(0).toUpperCase() || "?";

  const create = useMutation({
    mutationFn: () =>
      api.createPost({
        title: title.trim(),
        content: content.trim(),
        vulnerabilityId,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["community-posts"] });
      setTitle("");
      setContent("");
      setError(null);
      onClose();
    },
    onError: (err) => {
      setError(err instanceof ApiError ? err.message : "글 작성에 실패했습니다.");
    },
  });

  // 진입 시 제목 input focus + body scroll lock + ESC 닫기
  useEffect(() => {
    if (!open) return;
    const t = window.setTimeout(() => titleRef.current?.focus(), 80);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    return () => {
      window.clearTimeout(t);
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  const canSubmit = title.trim().length > 0 && content.trim().length > 0 && !create.isPending;

  const submit = () => {
    if (!title.trim() || !content.trim()) {
      setError("제목과 본문을 입력해 주세요.");
      return;
    }
    create.mutate();
  };

  const onContentKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // Cmd+Enter / Ctrl+Enter 로 빠른 게시
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      if (canSubmit) submit();
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="new-post-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-neutral-950/60 px-4 py-10 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="relative w-full max-w-2xl overflow-hidden rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── 헤더 ───────────────────────────────────────── */}
        <header className="flex items-start justify-between gap-3 border-b border-neutral-200 px-5 py-4 dark:border-neutral-800">
          <div className="flex items-center gap-3">
            <span
              className={cn(
                "flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm font-semibold",
                user?.isAdmin
                  ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-200"
                  : "bg-sky-100 text-sky-800 dark:bg-sky-500/20 dark:text-sky-200",
              )}
            >
              {initial}
            </span>
            <div className="min-w-0">
              <h2
                id="new-post-title"
                className="text-base font-semibold text-neutral-900 dark:text-neutral-100"
              >
                새 글 작성
              </h2>
              <p className="mt-0.5 flex items-center gap-1.5 text-xs text-neutral-600 dark:text-neutral-400">
                <UserIcon className="h-3 w-3" />
                {displayName}
                {user?.isAdmin && (
                  <span className="ml-1 inline-flex items-center rounded-full bg-amber-100 px-1.5 py-px text-[10px] font-medium text-amber-800 dark:bg-amber-500/15 dark:text-amber-200">
                    관리자
                  </span>
                )}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {vulnerabilityId && (
              <span
                className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2.5 py-1 text-[11px] font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200"
                title="이 CVE 에 연결되어 게시됩니다"
              >
                <Hash className="h-3 w-3" />
                CVE 연결
              </span>
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="닫기"
              className="inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </header>

        {/* ── 본문 폼 ───────────────────────────────────── */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
          className="space-y-3 px-5 py-4"
        >
          <div className="space-y-1.5">
            <label
              htmlFor="np-title"
              className="flex items-baseline justify-between text-xs font-medium text-neutral-700 dark:text-neutral-300"
            >
              제목
              <span className="tabular-nums text-neutral-500 dark:text-neutral-500">
                {title.length} / {TITLE_MAX}
              </span>
            </label>
            <Input
              id="np-title"
              ref={titleRef}
              placeholder="한 줄 요약 — 핵심부터"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              maxLength={TITLE_MAX}
              required
              className="text-[15px]"
            />
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="np-content"
              className="flex items-baseline justify-between text-xs font-medium text-neutral-700 dark:text-neutral-300"
            >
              본문
              <span className="tabular-nums text-neutral-500 dark:text-neutral-500">
                {content.length.toLocaleString()} / {BODY_MAX.toLocaleString()}
              </span>
            </label>
            <textarea
              id="np-content"
              className="block min-h-[220px] w-full resize-y rounded-lg border border-neutral-300 bg-white p-3 text-sm leading-relaxed text-neutral-900 placeholder:text-neutral-400 transition-colors focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:placeholder:text-neutral-500 dark:focus:ring-sky-500/30"
              placeholder="배경 · 발견 경위 · 영향 · 완화 방안 · 참고 링크 등 자유롭게.&#10;&#10;마크다운은 아직 지원하지 않습니다 — 일반 텍스트로 작성해 주세요."
              value={content}
              onChange={(e) => setContent(e.target.value)}
              onKeyDown={onContentKey}
              maxLength={BODY_MAX}
              required
            />
          </div>

          {error && (
            <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-300">
              {error}
            </p>
          )}
        </form>

        {/* ── 푸터 ───────────────────────────────────────── */}
        <footer className="flex items-center justify-between gap-3 border-t border-neutral-200 bg-neutral-50 px-5 py-3 dark:border-neutral-800 dark:bg-surface-2/50">
          {/* 단축키 안내는 데스크탑에서만 — 모바일에선 가용 폭이 좁아 푸터를 두 줄로 밀어내므로 숨김 */}
          <p className="hidden text-[11px] text-neutral-500 sm:block dark:text-neutral-500">
            <kbd className="rounded border border-neutral-300 bg-white px-1.5 py-0.5 text-[10px] font-mono shadow-sm dark:border-neutral-700 dark:bg-surface-1">
              ⌘ Enter
            </kbd>{" "}
            로 빠르게 게시 ·{" "}
            <kbd className="rounded border border-neutral-300 bg-white px-1.5 py-0.5 text-[10px] font-mono shadow-sm dark:border-neutral-700 dark:bg-surface-1">
              Esc
            </kbd>{" "}
            로 닫기
          </p>
          <div className="ml-auto flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={create.isPending}
              size="sm"
            >
              취소
            </Button>
            <Button
              type="button"
              onClick={submit}
              disabled={!canSubmit}
              size="sm"
              className="gap-1.5 bg-sky-500 text-white hover:bg-sky-600 disabled:opacity-50 dark:bg-sky-500 dark:hover:bg-sky-400"
            >
              {create.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Send className="h-3.5 w-3.5" />
              )}
              {create.isPending ? "게시 중…" : "게시"}
            </Button>
          </div>
        </footer>
      </div>
    </div>
  );
}
