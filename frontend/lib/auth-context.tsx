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
// 사용자 전환 시 *유지* 할 키만 KEEP, 나머지 ``kestrel:*`` 는 전부 클리어.
//
// PR 10-CP1 → 이후 KEEP_PREFIX 로 분석 히스토리 등을 *유지* 했었는데, 그 가정
// ("사용자 분리는 backend 가 보장하니 로컬 캐시는 안 비워도 됨")이 틀렸다(PR 10-FE):
// analysis-history / ai-analysis / qa / compare-history / comment-history /
// analysis-seen 캐시는 *user 별 네임스페이스가 없는 단일 키* 이고 UI(활동 센터·
// /analysis 탭)에 그대로 표시된다. 그래서 같은 브라우저에서 계정을 바꾸면 이전
// 사용자의 기록이 새 사용자(예: test)에게 노출됐다 — 명백한 데이터 격리 위반.
//
// 본인 기록 유실 우려는 없다: /analysis 페이지·활동 센터는 서버 /me/analyses
// (user-scoped) 를 다시 불러오므로 클리어 후 본인 계정으로 들어오면 서버에서
// 복원된다. ``-running`` 트랜잭션 마커도 전환 시 비워져야 정상(다른 사용자의
// 진행 중 작업 재시도 → 401 방지).
const LAST_USER_KEY = "kestrel:last-user-id";
// 사용자 전환 시 *유지* 할 키 / prefix. theme(개인 취향, 비-사용자 데이터)만 유지.
const KEEP_EXACT = new Set<string>([
  "kestrel:theme",
  LAST_USER_KEY,
]);
const KEEP_PREFIX: readonly string[] = [];

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
