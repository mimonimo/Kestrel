// Pending-analysis registry — separate from the completed-history
// list. The user can refresh the page mid-analysis; the QueryClient's
// in-memory in-flight state is lost, but this localStorage record
// keeps the "분석 중" indicator visible until the analysis settles or
// goes stale.

import { useEffect, useState } from "react";

const KEY = "kestrel:ai-analysis:running";
const STALE_MS = 10 * 60 * 1000;

export interface RunningEntry {
  cveId: string;
  startedAt: number;
}

function read(): RunningEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is RunningEntry =>
        e && typeof e.cveId === "string" && typeof e.startedAt === "number",
    );
  } catch {
    return [];
  }
}

function write(next: RunningEntry[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(next));
    window.dispatchEvent(new Event("kestrel:analysis-running-changed"));
  } catch {
    /* quota — skip */
  }
}

function prune(list: RunningEntry[]): RunningEntry[] {
  const cutoff = Date.now() - STALE_MS;
  return list.filter((e) => e.startedAt >= cutoff);
}

export function readRunningAnalyses(): RunningEntry[] {
  return prune(read());
}

export function markRunning(cveId: string): void {
  const filtered = read().filter((e) => e.cveId !== cveId);
  write(prune([...filtered, { cveId, startedAt: Date.now() }]));
}

export function clearRunning(cveId: string): void {
  write(prune(read().filter((e) => e.cveId !== cveId)));
}

export function useRunningAnalyses(): RunningEntry[] {
  const [list, setList] = useState<RunningEntry[]>([]);
  useEffect(() => {
    const sync = () => setList(readRunningAnalyses());
    sync();
    const interval = window.setInterval(sync, 30_000);
    window.addEventListener("kestrel:analysis-running-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("kestrel:analysis-running-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  return list;
}
