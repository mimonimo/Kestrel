"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import {
  Bug,
  Check,
  Lightbulb,
  Loader2,
  Megaphone,
  MessageSquarePlus,
  Send,
  ShieldAlert,
  X,
} from "lucide-react";

import { submitReport } from "@/lib/api";
import { useBodyScrollLock } from "@/lib/use-body-scroll-lock";
import { cn } from "@/lib/utils";

interface Cat {
  value: string;
  label: string;
  desc: string;
  icon: typeof Bug;
  /** 선택 시 강조 색 (light 기준, dark 변형 포함) */
  tone: string;
}

const CATEGORIES: Cat[] = [
  {
    value: "bug",
    label: "버그·오류",
    desc: "동작이 안 되거나 깨져요",
    icon: Bug,
    tone: "border-rose-400 bg-rose-50 text-rose-700 dark:border-rose-500/50 dark:bg-rose-500/15 dark:text-rose-200",
  },
  {
    value: "idea",
    label: "제안·의견",
    desc: "이런 기능이 있었으면",
    icon: Lightbulb,
    tone: "border-amber-400 bg-amber-50 text-amber-700 dark:border-amber-500/50 dark:bg-amber-500/15 dark:text-amber-200",
  },
  {
    value: "abuse",
    label: "부적절한 콘텐츠",
    desc: "스팸·악성·부적절",
    icon: ShieldAlert,
    tone: "border-violet-400 bg-violet-50 text-violet-700 dark:border-violet-500/50 dark:bg-violet-500/15 dark:text-violet-200",
  },
  {
    value: "other",
    label: "기타",
    desc: "그 외 무엇이든",
    icon: MessageSquarePlus,
    tone: "border-sky-400 bg-sky-50 text-sky-700 dark:border-sky-500/50 dark:bg-sky-500/15 dark:text-sky-200",
  },
];

const MAX = 2000;
const MIN = 5;

export function ReportButton() {
  const [open, setOpen] = useState(false);
  const [category, setCategory] = useState("bug");
  const [message, setMessage] = useState("");
  const [contact, setContact] = useState("");
  const [wantContact, setWantContact] = useState(false);
  const [state, setState] = useState<"idle" | "sending" | "done" | "error">("idle");
  const [error, setError] = useState("");

  useBodyScrollLock(open);

  const reset = () => {
    setCategory("bug");
    setMessage("");
    setContact("");
    setWantContact(false);
    setState("idle");
    setError("");
  };
  const close = () => {
    setOpen(false);
    setTimeout(reset, 200);
  };

  // ESC 닫기
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const submit = async () => {
    if (message.trim().length < MIN) {
      setError(`내용을 ${MIN}자 이상 입력해 주세요.`);
      return;
    }
    setState("sending");
    setError("");
    try {
      const url =
        typeof window !== "undefined"
          ? window.location.pathname + window.location.search
          : undefined;
      await submitReport({ category, message: message.trim(), url, contact: (wantContact && contact.trim()) || undefined });
      setState("done");
    } catch (e) {
      setState("error");
      setError(e instanceof Error ? e.message : "전송에 실패했습니다.");
    }
  };

  const tooShort = message.trim().length > 0 && message.trim().length < MIN;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1 text-neutral-600 transition-colors hover:text-sky-600 hover:underline dark:text-neutral-400 dark:hover:text-sky-300"
      >
        <Megaphone className="h-3.5 w-3.5" />
        문제 신고·의견
      </button>

      {open &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-[100] flex items-center justify-center bg-neutral-950/50 px-4 backdrop-blur-sm animate-in fade-in duration-150"
            onClick={close}
            role="dialog"
            aria-modal="true"
            aria-label="문제 신고·의견 보내기"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-lg overflow-hidden rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/10 animate-in zoom-in-95 duration-150 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/40"
            >
              {/* 헤더 */}
              <div className="flex items-start justify-between gap-3 border-b border-neutral-200 px-5 py-4 dark:border-neutral-800">
                <div className="flex items-start gap-3">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-sky-100 text-sky-600 dark:bg-sky-500/15 dark:text-sky-300">
                    <Megaphone className="h-5 w-5" />
                  </span>
                  <div>
                    <h2 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                      문제 신고·의견 보내기
                    </h2>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-neutral-500 dark:text-neutral-400">
                      불편한 점이나 좋은 아이디어를 알려주세요. 빠르게 반영하겠습니다.
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={close}
                  aria-label="닫기"
                  className="-mr-1 shrink-0 rounded-full p-1.5 text-neutral-400 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-surface-2 dark:hover:text-neutral-200"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {state === "done" ? (
                <div className="flex flex-col items-center gap-3 px-5 py-12 text-center">
                  <span className="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-500/20">
                    <Check className="h-6 w-6 text-emerald-600 dark:text-emerald-300" />
                  </span>
                  <div>
                    <p className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                      접수되었습니다. 감사합니다!
                    </p>
                    <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                      소중한 의견은 서비스 개선에 활용됩니다.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={close}
                    className="mt-1 rounded-full bg-sky-500 px-5 py-2 text-xs font-semibold text-white transition-colors hover:bg-sky-400"
                  >
                    닫기
                  </button>
                </div>
              ) : (
                <div className="space-y-3.5 px-5 py-4">
                  {/* 카테고리 — 컴팩트 칩 */}
                  <div className="flex flex-wrap gap-1.5">
                    {CATEGORIES.map((c) => {
                      const Icon = c.icon;
                      const selected = category === c.value;
                      return (
                        <button
                          key={c.value}
                          type="button"
                          onClick={() => setCategory(c.value)}
                          aria-pressed={selected}
                          title={c.desc}
                          className={cn(
                            "inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-colors",
                            selected
                              ? c.tone
                              : "border-neutral-200 text-neutral-600 hover:bg-neutral-50 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-surface-2",
                          )}
                        >
                          <Icon className="h-3.5 w-3.5" />
                          {c.label}
                        </button>
                      );
                    })}
                  </div>

                  {/* 내용 */}
                  <div>
                    <textarea
                      value={message}
                      onChange={(e) => {
                        setMessage(e.target.value);
                        if (error) setError("");
                      }}
                      rows={5}
                      maxLength={MAX}
                      autoFocus
                      placeholder="어떤 문제가 있었는지, 또는 의견을 자유롭게 남겨주세요.&#10;예: '취약점 조회에서 특정 필터를 누르면 페이지가 안 열려요'"
                      className="block w-full resize-none rounded-xl border border-neutral-300 bg-white px-3 py-2.5 text-sm text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:placeholder:text-neutral-500 dark:focus:ring-sky-500/30"
                    />
                    <div className="mt-1 flex items-center justify-between text-[10px]">
                      <span className={cn(tooShort ? "text-rose-500 dark:text-rose-400" : "text-neutral-400")}>
                        {tooShort ? `${MIN}자 이상 입력해 주세요` : "현재 페이지 주소가 함께 전송됩니다"}
                      </span>
                      <span className="tabular-nums text-neutral-400">
                        {message.length}/{MAX}
                      </span>
                    </div>
                  </div>

                  {/* 회신 연락처 — 슬림 토글 */}
                  <div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={wantContact}
                      onClick={() => setWantContact((v) => !v)}
                      className="inline-flex items-center gap-2 text-xs font-medium text-neutral-600 dark:text-neutral-400"
                    >
                      <span
                        className={cn(
                          "relative inline-flex h-4 w-7 shrink-0 items-center rounded-full transition-colors",
                          wantContact ? "bg-sky-500" : "bg-neutral-300 dark:bg-neutral-700",
                        )}
                      >
                        <span
                          className={cn(
                            "inline-block h-3 w-3 transform rounded-full bg-white shadow transition-transform",
                            wantContact ? "translate-x-3.5" : "translate-x-0.5",
                          )}
                        />
                      </span>
                      결과 회신받기 <span className="font-normal text-neutral-400">(선택)</span>
                    </button>
                    {wantContact && (
                      <input
                        type="text"
                        value={contact}
                        onChange={(e) => setContact(e.target.value)}
                        maxLength={200}
                        autoFocus
                        placeholder="이메일 또는 전화번호"
                        className="mt-2 block w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:placeholder:text-neutral-500 dark:focus:ring-sky-500/30"
                      />
                    )}
                  </div>

                  {error && !tooShort && (
                    <p className="rounded-lg bg-rose-50 px-3 py-2 text-[11px] text-rose-700 dark:bg-rose-500/10 dark:text-rose-300">
                      {error}
                    </p>
                  )}

                  {/* 액션 */}
                  <div className="flex items-center justify-end gap-2 pt-1">
                    <button
                      type="button"
                      onClick={close}
                      className="rounded-lg px-3 py-1.5 text-xs font-medium text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:text-neutral-400 dark:hover:bg-surface-2"
                    >
                      취소
                    </button>
                    <button
                      type="button"
                      onClick={submit}
                      disabled={state === "sending" || message.trim().length < MIN}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {state === "sending" ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Send className="h-3.5 w-3.5" />
                      )}
                      보내기
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>,
          document.body,
        )}
    </>
  );
}
