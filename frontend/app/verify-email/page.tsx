"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";

import { ApiError, api } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

type State = "loading" | "success" | "error";

function readToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return new URLSearchParams(window.location.search).get("token");
  } catch {
    return null;
  }
}

export default function VerifyEmailPage() {
  const router = useRouter();
  const { refresh } = useAuth();
  const [state, setState] = useState<State>("loading");
  const [message, setMessage] = useState("");
  // StrictMode 의 이중 실행으로 일회성 토큰이 두 번 소비되지 않게 가드.
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    const token = readToken();
    if (!token) {
      setState("error");
      setMessage("인증 링크가 올바르지 않습니다. 메일의 링크를 다시 확인해 주세요.");
      return;
    }

    (async () => {
      try {
        await api.verifyEmail(token);
        // 인증 성공 시 백엔드가 세션 쿠키를 발급 → 컨텍스트 갱신 후 홈으로.
        await refresh();
        setState("success");
        setMessage("이메일 인증이 완료되었습니다. 잠시 후 메인으로 이동합니다.");
        setTimeout(() => router.replace("/" as never), 1500);
      } catch (err) {
        setState("error");
        setMessage(
          err instanceof ApiError && err.message
            ? err.message
            : "인증에 실패했습니다. 링크가 만료되었을 수 있습니다.",
        );
      }
    })();
  }, [refresh, router]);

  return (
    <div className="mx-auto flex w-full max-w-md flex-col items-center gap-6 px-6 py-20 text-center">
      {state === "loading" && (
        <>
          <Loader2 className="h-8 w-8 animate-spin text-sky-500" />
          <p className="text-sm text-neutral-600 dark:text-neutral-400">이메일을 인증하는 중…</p>
        </>
      )}
      {state === "success" && (
        <>
          <CheckCircle2 className="h-10 w-10 text-emerald-500" />
          <h1 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            인증 완료
          </h1>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">{message}</p>
        </>
      )}
      {state === "error" && (
        <>
          <XCircle className="h-10 w-10 text-red-500" />
          <h1 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            인증 실패
          </h1>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">{message}</p>
          <div className="flex gap-3 text-sm">
            <Link
              href={"/login" as never}
              className="font-medium text-sky-600 hover:underline dark:text-sky-400"
            >
              로그인으로 가기
            </Link>
            <Link
              href={"/signup" as never}
              className="font-medium text-sky-600 hover:underline dark:text-sky-400"
            >
              다시 가입하기
            </Link>
          </div>
        </>
      )}
    </div>
  );
}
