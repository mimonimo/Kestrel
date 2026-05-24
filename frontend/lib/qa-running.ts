// Persist the in-flight follow-up Q&A request so a refresh during the
// ~30s Sonnet round-trip doesn't drop the user back to an empty input
// box. FollowUpThread reads this on mount and auto re-issues the
// request — the backend is stateless and just re-fires.

import { useEffect, useState } from "react";

const KEY_PREFIX = "kestrel:qa-running:";
const STALE_MS = 10 * 60 * 1000;

export interface RunningQa {
  cveId: string;
  question: string;
  startedAt: number;
}

function key(cveId: string): string {
  return KEY_PREFIX + cveId;
}

function read(cveId: string): RunningQa | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(key(cveId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as RunningQa;
    if (!parsed || typeof parsed.question !== "string" || typeof parsed.startedAt !== "number") {
      return null;
    }
    if (Date.now() - parsed.startedAt > STALE_MS) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function readRunningQa(cveId: string): RunningQa | null {
  return read(cveId);
}

export function markRunningQa(cveId: string, question: string): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      key(cveId),
      JSON.stringify({ cveId, question, startedAt: Date.now() }),
    );
    window.dispatchEvent(new Event("kestrel:qa-running-changed"));
  } catch {
    /* quota */
  }
}

export function clearRunningQa(cveId: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(key(cveId));
  window.dispatchEvent(new Event("kestrel:qa-running-changed"));
}

export function useRunningQa(cveId: string): RunningQa | null {
  const [r, setR] = useState<RunningQa | null>(null);
  useEffect(() => {
    const sync = () => setR(read(cveId));
    sync();
    window.addEventListener("kestrel:qa-running-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:qa-running-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, [cveId]);
  return r;
}
