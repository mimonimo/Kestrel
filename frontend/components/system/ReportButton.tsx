"use client";

import { useState } from "react";
import { createPortal } from "react-dom";
import { Check, Loader2, Megaphone, Send, X } from "lucide-react";

import { submitReport } from "@/lib/api";
import { cn } from "@/lib/utils";

const CATEGORIES: { value: string; label: string }[] = [
  { value: "bug", label: "버그/오류" },
  { value: "idea", label: "제안/의견" },
  { value: "abuse", label: "부적절한 콘텐츠" },
  { value: "other", label: "기타" },
];

export function ReportButton() {
  const [open, setOpen] = useState(false);
  const [category, setCategory] = useState("bug");
  const [message, setMessage] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "done" | "error">("idle");
  const [error, setError] = useState("");

  const reset = () => {
    setCategory("bug");
    setMessage("");
    setState("idle");
    setError("");
  };
  const close = () => {
    setOpen(false);
    // 닫은 뒤 다음 오픈을 위해 초기화(완료 상태였다면).
    setTimeout(reset, 200);
  };

  const submit = async () => {
    if (message.trim().length < 5) {
      setError("내용을 5자 이상 입력해 주세요.");
      return;
    }
    setState("sending");
    setError("");
    try {
      const url =
        typeof window !== "undefined"
          ? window.location.pathname + window.location.search
          : undefined;
      await submitReport({ category, message: message.trim(), url });
      setState("done");
    } catch (e) {
      setState("error");
      setError(e instanceof Error ? e.message : "전송에 실패했습니다.");
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1 text-neutral-600 hover:underline dark:text-neutral-400"
      >
        <Megaphone className="h-3.5 w-3.5" />
        문제 신고·의견
      </button>

      {open &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 px-4"
            onClick={close}
            role="dialog"
            aria-modal="true"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-md rounded-2xl border border-neutral-200 bg-white p-5 shadow-xl dark:border-neutral-800 dark:bg-surface-1"
            >
              <div className="flex items-center justify-between">
                <h2 className="flex items-center gap-2 text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                  <Megaphone className="h-4 w-4 text-sky-500" />
                  문제 신고·의견 보내기
                </h2>
                <button
                  type="button"
                  onClick={close}
                  aria-label="닫기"
                  className="rounded-full p-1 text-neutral-500 hover:bg-neutral-100 dark:hover:bg-surface-2"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {state === "done" ? (
                <div className="flex flex-col items-center gap-2 py-8 text-center">
                  <span className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-500/20">
                    <Check className="h-5 w-5 text-emerald-600 dark:text-emerald-300" />
                  </span>
                  <p className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
                    접수되었습니다. 감사합니다!
                  </p>
                  <button
                    type="button"
                    onClick={close}
                    className="mt-2 rounded-full bg-sky-500 px-4 py-1.5 text-xs font-semibold text-white hover:bg-sky-400"
                  >
                    닫기
                  </button>
                </div>
              ) : (
                <div className="mt-4 space-y-3">
                  <div className="flex flex-wrap gap-1.5">
                    {CATEGORIES.map((c) => (
                      <button
                        key={c.value}
                        type="button"
                        onClick={() => setCategory(c.value)}
                        className={cn(
                          "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                          category === c.value
                            ? "border-sky-400 bg-sky-100 text-sky-800 dark:border-sky-500/50 dark:bg-sky-500/20 dark:text-sky-200"
                            : "border-neutral-300 text-neutral-600 hover:border-sky-300 dark:border-neutral-700 dark:text-neutral-400",
                        )}
                      >
                        {c.label}
                      </button>
                    ))}
                  </div>
                  <textarea
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    rows={4}
                    maxLength={2000}
                    placeholder="어떤 문제가 있었는지, 또는 의견을 남겨주세요. (예: 특정 페이지가 안 열려요)"
                    className="block w-full resize-none rounded-lg border border-neutral-300 bg-white px-3 py-2 text-xs text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:focus:ring-sky-500/30"
                  />
                  {error && <p className="text-[11px] text-rose-600 dark:text-rose-300">{error}</p>}
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-neutral-400">
                      현재 페이지 주소가 함께 전송됩니다.
                    </span>
                    <button
                      type="button"
                      onClick={submit}
                      disabled={state === "sending"}
                      className="inline-flex items-center gap-1.5 rounded-full bg-sky-500 px-4 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-sky-400 disabled:opacity-50"
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
