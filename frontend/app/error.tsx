"use client";

import { useEffect } from "react";
import { AlertTriangle } from "lucide-react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // 개발/운영 콘솔에 남겨 디버깅. (Sentry 연동 시 자동 캡처)
    console.error(error);
  }, [error]);

  return (
    <div className="mx-auto flex min-h-[60vh] max-w-md flex-col items-center justify-center gap-5 px-6 text-center">
      <AlertTriangle className="h-10 w-10 text-amber-500" />
      <div>
        <h1 className="text-lg font-semibold text-neutral-100">문제가 발생했습니다</h1>
        <p className="mt-1.5 text-sm text-neutral-400">
          페이지를 표시하는 중 오류가 났어요. 다시 시도해 주세요. 문제가 계속되면 잠시 후 다시
          방문해 주세요.
        </p>
        {error.digest && (
          <p className="mt-2 font-mono text-[11px] text-neutral-600">오류 ID: {error.digest}</p>
        )}
      </div>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => reset()}
          className="rounded-full bg-sky-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-600"
        >
          다시 시도
        </button>
        <a
          href="/"
          className="rounded-full border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 transition-colors hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-surface-2"
        >
          홈으로
        </a>
      </div>
    </div>
  );
}
