"use client";

import { useCallback, useEffect, useState } from "react";

const KEY = "cvewatch:assets";

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
  window.dispatchEvent(new Event("cvewatch:assets"));
}

function uid(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export function useAssets() {
  const [list, setList] = useState<Asset[]>([]);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    setList(read());
    setReady(true);
    const sync = () => setList(read());
    window.addEventListener("cvewatch:assets", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("cvewatch:assets", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const add = useCallback((a: Omit<Asset, "id">) => {
    const next = [...read(), { ...a, id: uid() }];
    write(next);
    setList(next);
  }, []);

  const remove = useCallback((id: string) => {
    const next = read().filter((a) => a.id !== id);
    write(next);
    setList(next);
  }, []);

  return { list, ready, add, remove };
}
