"use client";

/**
 * 유휴(미사용) 세션 자동 로그아웃 가드.
 *
 * 로그인 상태에서 실제 사용자 활동(마우스·키보드·터치·스크롤)이
 * ``IDLE_LIMIT_MS`` 동안 없으면 자동 로그아웃하고 /login 으로 보낸다.
 * - 백그라운드 폴링/네트워크 요청은 활동으로 치지 않는다(자리 비우면 만료).
 * - last-activity 를 localStorage 로 공유해 여러 탭이 함께 동작한다.
 * - 서버 쿠키는 여전히 12h 절대만료(상한) — 본 가드는 그 위의 유휴 타임아웃.
 */
import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";

import { useAuth } from "@/lib/auth-context";

const IDLE_LIMIT_MS = 30 * 60_000; // 30분 무활동 시 로그아웃
const CHECK_INTERVAL_MS = 30_000; // 30초마다 점검
const WRITE_THROTTLE_MS = 5_000; // 활동 기록은 5초에 한 번만
const STORAGE_KEY = "kestrel:last-activity";

export function IdleLogoutGuard() {
  const { user, logout } = useAuth();
  const router = useRouter();
  const loggingOutRef = useRef(false);

  useEffect(() => {
    if (!user) return;
    loggingOutRef.current = false;

    const now = () => Date.now();
    const setLast = (t: number) => {
      try {
        window.localStorage.setItem(STORAGE_KEY, String(t));
      } catch {
        /* quota/SSR */
      }
    };
    const getLast = (): number => {
      try {
        return Number(window.localStorage.getItem(STORAGE_KEY)) || now();
      } catch {
        return now();
      }
    };

    // 마운트 시 활동 시각 초기화.
    setLast(now());
    let lastWrite = now();

    const onActivity = () => {
      const t = now();
      if (t - lastWrite >= WRITE_THROTTLE_MS) {
        lastWrite = t;
        setLast(t);
      }
    };

    const doLogout = async () => {
      if (loggingOutRef.current) return;
      loggingOutRef.current = true;
      try {
        await logout();
      } finally {
        router.replace("/login?reason=idle" as never);
      }
    };

    const check = () => {
      if (now() - getLast() >= IDLE_LIMIT_MS) doLogout();
    };

    const events: (keyof WindowEventMap)[] = [
      "mousemove",
      "mousedown",
      "keydown",
      "touchstart",
      "scroll",
      "wheel",
    ];
    events.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));
    const interval = window.setInterval(check, CHECK_INTERVAL_MS);
    const onVisible = () => {
      if (document.visibilityState === "visible") check();
    };
    document.addEventListener("visibilitychange", onVisible);

    return () => {
      events.forEach((e) => window.removeEventListener(e, onActivity));
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [user, logout, router]);

  return null;
}
