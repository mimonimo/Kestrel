"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "./api";
import { useAuth } from "./auth-context";

const KEY = "kestrel:assets";

export interface Asset {
  id: string;
  vendor: string;
  product: string;
  version?: string;
}

function read(): Asset[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Asset[]) : [];
  } catch {
    return [];
  }
}

function write(list: Asset[]) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(KEY, JSON.stringify(list));
  window.dispatchEvent(new Event("kestrel:assets"));
}

function uid(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

// 서버 저장 형식(vendor/product)만 보냄 — version 은 매칭/알림에 안 쓰임(/match 도 동일).
function toServer(list: Asset[]): { vendor: string; product: string }[] {
  return list.map(({ vendor, product }) => ({ vendor, product }));
}

export function useAssets() {
  const { user } = useAuth();
  const [list, setList] = useState<Asset[]>([]);
  const [ready, setReady] = useState(false);
  const syncedFor = useRef<string | null>(null);

  useEffect(() => {
    setList(read());
    setReady(true);
    const sync = () => setList(read());
    window.addEventListener("kestrel:assets", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:assets", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  // 로그인 사용자: 서버를 진실원으로. 단, 서버가 비어 있고 로컬에 자산이 있으면
  // (localStorage 로 쓰던 사용자가 막 로그인) 로컬 → 서버 1회 이관. (PR 10-FB)
  useEffect(() => {
    if (!ready || !user) return;
    if (syncedFor.current === user.id) return;
    syncedFor.current = user.id;
    (async () => {
      try {
        const res = await api.getSavedAssets();
        const local = read();
        if (res.assets.length === 0 && local.length > 0) {
          await api.putSavedAssets(toServer(local)); // 이관
          return; // 로컬 유지
        }
        const merged: Asset[] = res.assets.map((a) => ({
          id: uid(),
          vendor: a.vendor,
          product: a.product,
        }));
        write(merged);
        setList(merged);
      } catch {
        // 서버 동기화 실패해도 로컬 기준으로 계속 동작.
      }
    })();
  }, [ready, user]);

  // 로그인 사용자면 전체 집합을 서버에 PUT(best-effort).
  const pushServer = useCallback(
    (next: Asset[]) => {
      if (!user) return;
      api.putSavedAssets(toServer(next)).catch(() => {});
    },
    [user],
  );

  const add = useCallback(
    (a: Omit<Asset, "id">) => {
      const next = [...read(), { ...a, id: uid() }];
      write(next);
      setList(next);
      pushServer(next);
    },
    [pushServer],
  );

  const remove = useCallback(
    (id: string) => {
      const next = read().filter((a) => a.id !== id);
      write(next);
      setList(next);
      pushServer(next);
    },
    [pushServer],
  );

  return { list, ready, add, remove };
}
