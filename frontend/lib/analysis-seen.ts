// "활동 센터에서 확인했음" 표식. 분석 기록 자체는 /analysis 탭에서
// 그대로 살아 있어야 하므로 별도 localStorage 키로 관리합니다.
// FloatingDock 은 unseen 항목만 카운트·렌더, 클릭 시 markSeen.

import { useEffect, useState } from "react";

const KEY = "kestrel:analysis-seen";

function read(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed)
      ? parsed.filter((x): x is string => typeof x === "string")
      : [];
  } catch {
    return [];
  }
}

function write(ids: string[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(ids));
    window.dispatchEvent(new Event("kestrel:analysis-seen-changed"));
  } catch {
    /* quota */
  }
}

export function markAnalysisSeen(cveId: string): void {
  const existing = new Set(read());
  if (existing.has(cveId)) return;
  existing.add(cveId);
  write(Array.from(existing));
}

export function markAllAnalysisSeen(cveIds: string[]): void {
  const existing = new Set(read());
  let changed = false;
  for (const id of cveIds) {
    if (!existing.has(id)) {
      existing.add(id);
      changed = true;
    }
  }
  if (changed) write(Array.from(existing));
}

export function clearAnalysisSeen(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(KEY);
  window.dispatchEvent(new Event("kestrel:analysis-seen-changed"));
}

export function useAnalysisSeen(): Set<string> {
  const [seen, setSeen] = useState<Set<string>>(() => new Set(read()));
  useEffect(() => {
    const sync = () => setSeen(new Set(read()));
    sync();
    window.addEventListener("kestrel:analysis-seen-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:analysis-seen-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  return seen;
}
