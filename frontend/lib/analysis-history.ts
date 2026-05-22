// Cross-CVE history of AI analyses, separate from the per-CVE cached
// result that AiAnalysisPanel uses for "이전 분석 보기" recall.
//
// Stored as a single localStorage key (capped at 50 entries) so the
// AnalysisHistoryButton popover can list every CVE the user has ever
// analyzed without iterating the per-CVE cache prefix.

import { useEffect, useState } from "react";

const HISTORY_KEY = "kestrel:ai-analysis:history";
const MAX_ENTRIES = 50;

export interface AnalysisHistoryEntry {
  cveId: string;
  timestamp: number; // epoch ms
  attackMethod: string; // short excerpt
  payloadCount: number;
  mitigationCount: number;
}

export function readAnalysisHistory(): AnalysisHistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is AnalysisHistoryEntry =>
        e &&
        typeof e.cveId === "string" &&
        typeof e.timestamp === "number" &&
        typeof e.attackMethod === "string",
    );
  } catch {
    return [];
  }
}

export function recordAnalysisHistory(entry: Omit<AnalysisHistoryEntry, "timestamp"> & { timestamp?: number }): void {
  if (typeof window === "undefined") return;
  const existing = readAnalysisHistory();
  // Dedupe by cveId — keep only the most recent entry per CVE.
  const filtered = existing.filter((e) => e.cveId !== entry.cveId);
  const next: AnalysisHistoryEntry = {
    cveId: entry.cveId,
    timestamp: entry.timestamp ?? Date.now(),
    attackMethod: entry.attackMethod,
    payloadCount: entry.payloadCount,
    mitigationCount: entry.mitigationCount,
  };
  const merged = [next, ...filtered].slice(0, MAX_ENTRIES);
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(merged));
    window.dispatchEvent(new Event("kestrel:analysis-history-changed"));
  } catch {
    // Quota — silently skip; the in-memory current panel still works.
  }
}

export function clearAnalysisHistory(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(HISTORY_KEY);
  window.dispatchEvent(new Event("kestrel:analysis-history-changed"));
}

export function deleteAnalysisHistoryEntry(cveId: string): void {
  if (typeof window === "undefined") return;
  const next = readAnalysisHistory().filter((e) => e.cveId !== cveId);
  window.localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
  window.dispatchEvent(new Event("kestrel:analysis-history-changed"));
}

// React hook returning a Set of CVE IDs that have a recorded analysis.
// Subscribes to the local storage change event so CveListItem markers
// update immediately when a new analysis completes in another tab/panel.
export function useAnalyzedCveIds(): Set<string> {
  const [ids, setIds] = useState<Set<string>>(() => {
    if (typeof window === "undefined") return new Set();
    return new Set(readAnalysisHistory().map((e) => e.cveId));
  });
  useEffect(() => {
    const sync = () => setIds(new Set(readAnalysisHistory().map((e) => e.cveId)));
    sync();
    window.addEventListener("kestrel:analysis-history-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:analysis-history-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  return ids;
}
