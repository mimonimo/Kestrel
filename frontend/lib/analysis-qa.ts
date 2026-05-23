// Per-CVE follow-up Q&A history. Lives in localStorage so a user can
// keep building a thread across navigation without the server having
// to track sessions — the backend /analysis/ask call is stateless and
// just re-receives the running history on each turn.

import { useCallback, useEffect, useState } from "react";

const KEY_PREFIX = "kestrel:ai-analysis-qa:";
const MAX_TURNS = 30;

export interface QaTurn {
  question: string;
  answer: string;
  timestamp: number;
}

function key(cveId: string): string {
  return KEY_PREFIX + cveId;
}

export function readQaHistory(cveId: string): QaTurn[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(key(cveId));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (t): t is QaTurn =>
        t &&
        typeof t.question === "string" &&
        typeof t.answer === "string" &&
        typeof t.timestamp === "number",
    );
  } catch {
    return [];
  }
}

export function appendQaTurn(cveId: string, turn: Omit<QaTurn, "timestamp"> & { timestamp?: number }): void {
  if (typeof window === "undefined") return;
  const next: QaTurn = {
    question: turn.question,
    answer: turn.answer,
    timestamp: turn.timestamp ?? Date.now(),
  };
  const merged = [...readQaHistory(cveId), next].slice(-MAX_TURNS);
  try {
    window.localStorage.setItem(key(cveId), JSON.stringify(merged));
    window.dispatchEvent(new Event("kestrel:analysis-qa-changed"));
  } catch {
    /* quota — skip */
  }
}

export function clearQaHistory(cveId: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(key(cveId));
  window.dispatchEvent(new Event("kestrel:analysis-qa-changed"));
}

export function useQaHistory(cveId: string): {
  turns: QaTurn[];
  refresh: () => void;
} {
  const [turns, setTurns] = useState<QaTurn[]>([]);
  const refresh = useCallback(() => setTurns(readQaHistory(cveId)), [cveId]);
  useEffect(() => {
    refresh();
    const sync = () => refresh();
    window.addEventListener("kestrel:analysis-qa-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:analysis-qa-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, [refresh]);
  return { turns, refresh };
}
