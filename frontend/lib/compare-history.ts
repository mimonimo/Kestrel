// Persist the last few CVE-pattern comparison runs in localStorage so
// the user can reopen the /analysis 패턴 비교 탭 after a refresh or a
// navigation away and still see what was compared + the result.

import { useEffect, useState } from "react";
import type { CompareResponse } from "./api";

const KEY = "kestrel:compare-history";
const MAX_ENTRIES = 20;

export interface CompareHistoryEntry {
  id: string;            // composite key of sorted cve ids
  timestamp: number;     // epoch ms
  cveIds: string[];      // ordered as the user picked them
  result: CompareResponse;
}

function makeId(cveIds: string[]): string {
  return [...cveIds].sort().join("|");
}

export function readCompareHistory(): CompareHistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is CompareHistoryEntry =>
        e &&
        typeof e.id === "string" &&
        typeof e.timestamp === "number" &&
        Array.isArray(e.cveIds) &&
        e.result &&
        typeof e.result === "object",
    );
  } catch {
    return [];
  }
}

export function recordCompareHistory(cveIds: string[], result: CompareResponse): CompareHistoryEntry {
  const entry: CompareHistoryEntry = {
    id: makeId(cveIds),
    timestamp: Date.now(),
    cveIds: [...cveIds],
    result,
  };
  if (typeof window === "undefined") return entry;
  const existing = readCompareHistory().filter((e) => e.id !== entry.id);
  const merged = [entry, ...existing].slice(0, MAX_ENTRIES);
  try {
    window.localStorage.setItem(KEY, JSON.stringify(merged));
    window.dispatchEvent(new Event("kestrel:compare-history-changed"));
  } catch {
    /* quota — skip */
  }
  return entry;
}

export function deleteCompareHistory(id: string): void {
  if (typeof window === "undefined") return;
  const next = readCompareHistory().filter((e) => e.id !== id);
  window.localStorage.setItem(KEY, JSON.stringify(next));
  window.dispatchEvent(new Event("kestrel:compare-history-changed"));
}

export function clearCompareHistory(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(KEY);
  window.dispatchEvent(new Event("kestrel:compare-history-changed"));
}

export function useCompareHistory(): CompareHistoryEntry[] {
  const [entries, setEntries] = useState<CompareHistoryEntry[]>([]);
  useEffect(() => {
    const sync = () => setEntries(readCompareHistory());
    sync();
    window.addEventListener("kestrel:compare-history-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:compare-history-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  return entries;
}
