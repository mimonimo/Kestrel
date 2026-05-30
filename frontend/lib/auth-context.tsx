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

// 사용자 분리 캐시 (PR 10-CP1):
// 분석 히스토리·캐시된 AI 분석·QA·즐겨찾기·티켓 메모 등은 localStorage 에
// 영속화되어 있어 사용자가 바뀌어도 이전 사용자의 데이터가 그대로 보였다.
// 로그인 / 로그아웃 / 사용자 전환 시점에 user-specific 캐시를 모두 비운다.
// 보존 키 (theme 등 사용자 무관) 는 명시적으로 keep-list 에 둔다.
const LAST_USER_KEY = "kestrel:last-user-id";
const KEEP_KEYS = new Set<string>(["kestrel:theme", LAST_USER_KEY]);

function clearUserScopedLocal(): void {
  if (typeof window === "undefined") return;
  try {
    const toRemove: string[] = [];
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      if (k && k.startsWith("kestrel:") && !KEEP_KEYS.has(k)) toRemove.push(k);
    }
    for (const k of toRemove) window.localStorage.removeItem(k);
    // 캐시 클리어 후 화면이 즉시 새 상태를 반영하도록 동기화 이벤트 발행.
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
