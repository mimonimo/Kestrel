"use client";

import { useCallback, useEffect, useState } from "react";

const KEY = "cvewatch:bookmarks";

function read(): Set<string> {
  if (typeof window === "undefined") return new Set();
  try {
    const raw = window.localStorage.getItem(KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch {
    return new Set();
  }
}

function write(set: Set<string>) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(KEY, JSON.stringify([...set]));
  window.dispatchEvent(new Event("cvewatch:bookmarks"));
}

export function useBookmarks() {
  const [set, setSet] = useState<Set<string>>(() => new Set());
  const [ready, setReady] = useState(false);

  useEffect(() => {
    setSet(read());
    setReady(true);
    const sync = () => setSet(read());
    window.addEventListener("cvewatch:bookmarks", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("cvewatch:bookmarks", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const toggle = useCallback((cveId: string) => {
    const next = read();
    if (next.has(cveId)) next.delete(cveId);
    else next.add(cveId);
    write(next);
    setSet(next);
  }, []);

  const has = useCallback((cveId: string) => set.has(cveId), [set]);

  return { set, has, toggle, ready, count: set.size };
}
