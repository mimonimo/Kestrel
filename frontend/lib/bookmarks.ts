"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "./api";

const CACHE_KEY = "cvewatch:bookmarks";
const SYNC_EVENT = "cvewatch:bookmarks";

function readCache(): Set<string> {
  if (typeof window === "undefined") return new Set();
  try {
    const raw = window.localStorage.getItem(CACHE_KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch {
    return new Set();
  }
}

function writeCache(set: Set<string>) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(CACHE_KEY, JSON.stringify([...set]));
  } catch {
    /* ignore quota */
  }
  window.dispatchEvent(new Event(SYNC_EVENT));
}

export function useBookmarks() {
  const [set, setSet] = useState<Set<string>>(() => new Set());
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const cached = readCache();
    setSet(cached);

    api
      .getBookmarks()
      .then((res) => {
        if (cancelled) return;
        const next = new Set(res.items.map((b) => b.cveId));
        writeCache(next);
        setSet(next);
      })
      .catch(() => {
        /* offline / backend down — keep cache */
      })
      .finally(() => {
        if (!cancelled) setReady(true);
      });

    const sync = () => setSet(readCache());
    window.addEventListener(SYNC_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      cancelled = true;
      window.removeEventListener(SYNC_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const toggle = useCallback((cveId: string) => {
    const current = readCache();
    const wasOn = current.has(cveId);
    const next = new Set(current);
    if (wasOn) next.delete(cveId);
    else next.add(cveId);
    writeCache(next);
    setSet(next);

    const op = wasOn ? api.removeBookmark(cveId) : api.addBookmark(cveId);
    op.catch(() => {
      const reverted = new Set(readCache());
      if (wasOn) reverted.add(cveId);
      else reverted.delete(cveId);
      writeCache(reverted);
      setSet(reverted);
    });
  }, []);

  const has = useCallback((cveId: string) => set.has(cveId), [set]);

  return { set, has, toggle, ready, count: set.size };
}
