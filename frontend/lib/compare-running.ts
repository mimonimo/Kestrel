// Persist the *in-flight* CVE pattern-compare request so that a refresh
// during the 1-3 minute Sonnet call doesn't drop the user back to an
// empty CompareTab. CompareTab reads this on mount and auto re-issues
// the request (the backend is stateless — we just re-fire).

import { useEffect, useState } from "react";

const KEY = "kestrel:compare-running";
const STALE_MS = 10 * 60 * 1000;

export interface RunningCompare {
  cveIds: string[];
  startedAt: number;
}

function read(): RunningCompare | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as RunningCompare;
    if (!parsed || !Array.isArray(parsed.cveIds) || typeof parsed.startedAt !== "number") {
      return null;
    }
    if (Date.now() - parsed.startedAt > STALE_MS) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function readRunningCompare(): RunningCompare | null {
  return read();
}

export function markRunningCompare(cveIds: string[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      KEY,
      JSON.stringify({ cveIds: [...cveIds], startedAt: Date.now() }),
    );
    window.dispatchEvent(new Event("kestrel:compare-running-changed"));
  } catch {
    /* quota */
  }
}

export function clearRunningCompare(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(KEY);
  window.dispatchEvent(new Event("kestrel:compare-running-changed"));
}

export function useRunningCompare(): RunningCompare | null {
  const [r, setR] = useState<RunningCompare | null>(null);
  useEffect(() => {
    const sync = () => setR(read());
    sync();
    window.addEventListener("kestrel:compare-running-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:compare-running-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  return r;
}
