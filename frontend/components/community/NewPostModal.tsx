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
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Hash, Loader2, Search, Send, User as UserIcon, X } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { useDebounce } from "@/hooks/useDebounce";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { useBodyScrollLock } from "@/lib/use-body-scroll-lock";

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
  useBodyScrollLock(open);
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);
  const titleRef = useRef<HTMLInputElement>(null);

  // CVE 연결 — CVE 상세에서 열리면(vulnerabilityId prop) 고정, 커뮤니티에서
  // 열리면 검색해서 직접 첨부할 수 있다.
  const locked = !!vulnerabilityId;
  const [attached, setAttached] = useState<{ cveId: string; title?: string } | null>(
    vulnerabilityId ? { cveId: vulnerabilityId } : null,
  );
  const [cveQuery, setCveQuery] = useState("");
  const debouncedCve = useDebounce(cveQuery, 250);
  const cveSearch = useQuery({
    queryKey: ["post-cve-search", debouncedCve],
    queryFn: () => api.searchVulnerabilities({ query: debouncedCve }, 1, 8),
    enabled: open && !locked && !attached && debouncedCve.trim().length >= 2,
    staleTime: 30_000,
  });

  const displayName = (user?.nickname || user?.username || "").trim();
  const initial = displayName.trim().charAt(0).toUpperCase() || "?";

  const create = useMutation({
    mutationFn: () =>
      api.createPost({
        title: title.trim(),
        content: content.trim(),
        vulnerabilityId: attached?.cveId,
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

  // 진입 시 제목 input focus + body scroll lock + ESC 닫기.
  // 열릴 때마다 CVE 연결 상태를 prop 기준으로 초기화한다.
  useEffect(() => {
    if (!open) return;
    setAttached(vulnerabilityId ? { cveId: vulnerabilityId } : null);
    setCveQuery("");
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
  }, [open, onClose, vulnerabilityId]);

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
            {attached && (
              <span
                className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2.5 py-1 text-[11px] font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200"
                title="이 CVE 에 연결되어 게시됩니다"
              >
                <Hash className="h-3 w-3" />
                {attached.cveId}
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

          {/* CVE 연결 (선택) — CVE 상세에서 열렸으면(locked) 헤더 칩으로 고정 표시,
              커뮤니티에서 열렸으면 검색해 직접 연결할 수 있다. */}
          {!locked && (
            <div className="space-y-1.5">
              <label
                htmlFor="np-cve"
                className="block text-xs font-medium text-neutral-700 dark:text-neutral-300"
              >
                연결할 CVE <span className="font-normal text-neutral-500">(선택)</span>
              </label>
              {attached ? (
                <div className="flex items-center justify-between gap-2 rounded-lg border border-violet-200 bg-violet-50 px-3 py-2 text-sm dark:border-violet-500/30 dark:bg-violet-500/10">
                  <span className="inline-flex min-w-0 items-center gap-1.5 font-medium text-violet-800 dark:text-violet-200">
                    <Hash className="h-3.5 w-3.5 shrink-0" />
                    <span className="shrink-0">{attached.cveId}</span>
                    {attached.title && (
                      <span className="truncate font-normal text-violet-700/80 dark:text-violet-300/80">
                        — {attached.title}
                      </span>
                    )}
                  </span>
                  <button
                    type="button"
                    onClick={() => setAttached(null)}
                    aria-label="CVE 연결 해제"
                    className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-violet-700 transition-colors hover:bg-violet-200 dark:text-violet-300 dark:hover:bg-violet-500/20"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              ) : (
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-neutral-500" />
                  <input
                    id="np-cve"
                    type="search"
                    value={cveQuery}
                    onChange={(e) => setCveQuery(e.target.value)}
                    placeholder="CVE ID · 제품명 · 키워드로 검색해 연결"
                    autoComplete="off"
                    className="block w-full rounded-lg border border-neutral-300 bg-white py-2 pl-9 pr-3 text-sm text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:placeholder:text-neutral-500 dark:focus:ring-sky-500/30"
                  />
                  {debouncedCve.trim().length >= 2 && (
                    <div className="absolute left-0 right-0 top-full z-10 mt-1 max-h-64 overflow-y-auto rounded-lg border border-neutral-200 bg-white py-1 shadow-lg dark:border-neutral-700 dark:bg-surface-2">
                      {cveSearch.isPending ? (
                        <p className="flex items-center gap-2 px-3 py-2 text-xs text-neutral-500">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" /> 검색 중…
                        </p>
                      ) : cveSearch.data && cveSearch.data.items.length > 0 ? (
                        <ul>
                          {cveSearch.data.items.map((v) => (
                            <li key={v.cveId}>
                              <button
                                type="button"
                                onClick={() => {
                                  setAttached({ cveId: v.cveId, title: v.title });
                                  setCveQuery("");
                                }}
                                className="flex w-full items-start gap-2 px-3 py-2 text-left transition-colors hover:bg-sky-50 dark:hover:bg-sky-500/10"
                              >
                                <span className="shrink-0 font-mono text-[11px] font-semibold text-sky-700 dark:text-sky-300">
                                  {v.cveId}
                                </span>
                                <span className="min-w-0 flex-1 truncate text-xs text-neutral-700 dark:text-neutral-300">
                                  {v.title}
                                </span>
                              </button>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="px-3 py-2 text-xs text-neutral-500">
                          일치하는 CVE 가 없어요.
                        </p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

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
              placeholder="배경 · 발견 경위 · 영향 · 완화 방안 · 참고 링크 등 자유롭게.&#10;&#10;마크다운을 지원합니다 — 제목(#), 목록(-), 코드(`), 링크 등을 쓸 수 있어요."
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
