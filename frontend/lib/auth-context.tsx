"use client";

/**
 * AuthContext (PR 10-CN).
 *
 * 세션 식별은 백엔드가 발행하는 HttpOnly 쿠키 (``access_token``) — JS 는
 * 토큰 자체를 읽을 수 없다. 그래서 마운트 시 ``/auth/me`` 한 번 호출해
 * 현재 세션 사용자 객체를 가져오고, 401 이면 비로그인으로 간주한다.
 *
 * 절대 토큰 자체를 localStorage 에 저장하지 않는다 (XSS 시 탈취 우려).
 * 사용자 객체만 메모리에 두고, 로그아웃 시 서버가 쿠키를 무효화.
 */

import { createContext, useCallback, useContext, useEffect, useState } from "react";

import { ApiError, api, type AuthUser } from "./api";

// 사용자 분리 캐시 (PR 10-CP1 / 보강 PR 10-CP1.2).
//
// 1차 (PR 10-CP1) 에선 사용자 전환 시 ``kestrel:*`` 전체를 일괄 클리어해
// 다른 사용자의 흔적을 제거했는데, 본인 분석 기록까지 함께 사라진다는
// 보고 ("분석 기록은 유지 되어야지 왜 지워지니") 가 들어왔다.
//
// 분석 기록 / 즐겨찾기 / Q&A / 비교 히스토리·캐시된 분석 결과는 backend
// 가 user-scoped 로 영구 저장한다 (DB AnalysisResult / bookmarks.user_id /
// /me/analyses 등). 사용자 분리는 backend 응답 자체로 보장되므로 로컬
// 캐시까지 강제로 비울 필요가 없다.
//
// 반면 ``-running`` 마커 (refresh-running / analysis-running / qa-running /
// compare-running) 같은 트랜잭션 상태는 사용자 전환 시 반드시 비워야 한다 —
// 다른 사용자의 진행 중 작업이 새 사용자에게 자동 재시도되면 401 으로 깨진다.
const LAST_USER_KEY = "kestrel:last-user-id";
// 사용자 전환 시 *유지* 할 키 / prefix.
const KEEP_EXACT = new Set<string>([
  "kestrel:theme",
  LAST_USER_KEY,
]);
const KEEP_PREFIX = [
  "kestrel:analysis-history",   // 분석 히스토리
  "kestrel:compare-history",    // 비교 히스토리
  "kestrel:comment-history",    // 내 댓글 히스토리
  "kestrel:ai-analysis",        // 캐시된 분석 결과 (CVE 별)
  "kestrel:qa:",                // Q&A 히스토리 (CVE 별)
  "kestrel:bookmarks",          // 즐겨찾기 캐시 (backend 가 user-scoped 라 자동 갱신)
  "kestrel:analysis-seen",      // 알림 읽음 표시
] as const;

function shouldKeep(k: string): boolean {
  if (KEEP_EXACT.has(k)) return true;
  for (const p of KEEP_PREFIX) {
    if (k === p || k.startsWith(p + ":") || k.startsWith(p)) return true;
  }
  return false;
}

function clearUserScopedLocal(): void {
  if (typeof window === "undefined") return;
  try {
    const toRemove: string[] = [];
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      if (k && k.startsWith("kestrel:") && !shouldKeep(k)) toRemove.push(k);
    }
    for (const k of toRemove) window.localStorage.removeItem(k);
    // 즐겨찾기는 KEEP 이지만 로그아웃 직후엔 다음 사용자가 backend 동기화 전까지
    // 이전 사용자 목록을 잠시 보지 않도록 비워 둔다 — useBookmarks 가 즉시 다시 채움.
    window.localStorage.removeItem("kestrel:bookmarks");
    window.dispatchEvent(new Event("kestrel:bookmarks"));
    window.dispatchEvent(new Event("kestrel:analysis-history-changed"));
  } catch {
    /* ignore */
  }
}

function reconcileUserCaches(currentUserId: string | null): void {
  if (typeof window === "undefined") return;
  try {
    const prev = window.localStorage.getItem(LAST_USER_KEY);
    // 로그인/로그아웃 둘 다 — prev 와 current 가 다르면 캐시 갈아엎음.
    if (prev !== currentUserId) {
      clearUserScopedLocal();
      if (currentUserId) {
        window.localStorage.setItem(LAST_USER_KEY, currentUserId);
      } else {
        window.localStorage.removeItem(LAST_USER_KEY);
      }
    }
  } catch {
    /* ignore */
  }
}

interface AuthState {
  user: AuthUser | null;
  loading: boolean;
  refresh: () => Promise<void>;
  login: (email: string, password: string) => Promise<AuthUser>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const me = await api.getAuthMe();
      reconcileUserCaches(me.id);
      setUser(me);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        reconcileUserCaches(null);
        setUser(null);
      } else {
        // 네트워크/기타 — 로그인 상태를 알 수 없음. null 로 두되 다음 시도에서 복구.
        setUser(null);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const login = useCallback<AuthState["login"]>(
    async (email, password) => {
      const me = await api.login({ email, password });
      reconcileUserCaches(me.id);
      setUser(me);
      return me;
    },
    [],
  );

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      reconcileUserCaches(null);
      setUser(null);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <Ctx.Provider value={{ user, loading, refresh, login, logout }}>{children}</Ctx.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}

/** 로그인 필요 액션을 시도하기 전에 호출. 비로그인이면 /login 으로 보내며
 *  성공 후 돌아올 경로를 ``next`` 쿼리로 넘긴다. */
export function useRequireAuth() {
  const { user, loading } = useAuth();
  return (next?: string) => {
    if (loading) return null;
    if (user) return user;
    if (typeof window !== "undefined") {
      const target = next ?? window.location.pathname + window.location.search;
      window.location.href = `/login?next=${encodeURIComponent(target)}`;
    }
    return null;
  };
}
