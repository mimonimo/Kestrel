// "활동 센터에서 확인했음" 표식. 분석 기록 자체는 /analysis 탭에서
// 그대로 살아 있어야 하므로 별도 localStorage 키로 관리합니다.
// FloatingDock 은 unseen 항목만 카운트·렌더, 클릭 시 markSeen.

import { useEffect, useState } from "react";

// 사용자별 네임스페이스 — 로그아웃/재로그인·계정 전환 시에도 본인 "읽음"
// 상태가 유지·격리되도록 last-user-id 로 키를 분리한다. (PR 10-FG)
// 비네임스페이스 단일 키였을 때는 로그아웃 시 캐시 클리어로 seen 이 날아가
// 재로그인하면 모든 분석이 다시 "새 알림"으로 떴다 — 그 회귀를 막는다.
const BASE = "kestrel:analysis-seen";
const LAST_USER_KEY = "kestrel:last-user-id";

function storageKey(): string {
  if (typeof window === "undefined") return BASE;
  try {
    const uid = window.localStorage.getItem(LAST_USER_KEY);
    return uid ? `${BASE}:${uid}` : BASE;
  } catch {
    return BASE;
  }
}

function read(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(storageKey());
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
    window.localStorage.setItem(storageKey(), JSON.stringify(ids));
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
  window.localStorage.removeItem(storageKey());
  window.dispatchEvent(new Event("kestrel:analysis-seen-changed"));
}

// 최초 1회 기준선 — 이미 보유한(서버에서 복원된) 분석들은 "새 알림"이 아니라
// 이미 한 작업이므로, 사용자별로 처음 동기화될 때 한 번만 모두 읽음 처리한다.
// 이후 새로 완료되는 분석만 활동센터에 새 알림으로 뜬다. (PR 10-FG)
const INIT_BASE = "kestrel:analysis-seen-init";

function initKey(): string {
  if (typeof window === "undefined") return INIT_BASE;
  try {
    const uid = window.localStorage.getItem(LAST_USER_KEY);
    return uid ? `${INIT_BASE}:${uid}` : INIT_BASE;
  } catch {
    return INIT_BASE;
  }
}

export function ensureSeenBaseline(cveIds: string[]): void {
  if (typeof window === "undefined") return;
  try {
    if (window.localStorage.getItem(initKey())) return; // 이미 기준선 설정됨
    const set = new Set(read());
    for (const id of cveIds) set.add(id);
    window.localStorage.setItem(storageKey(), JSON.stringify(Array.from(set)));
    window.localStorage.setItem(initKey(), "1");
    window.dispatchEvent(new Event("kestrel:analysis-seen-changed"));
  } catch {
    /* quota */
  }
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
