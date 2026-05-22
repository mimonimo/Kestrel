// Local history of comments the user has authored. We don't have a
// dedicated "내 댓글" backend endpoint (the comments API is by-post or
// by-CVE, not by-client_id) so we mirror submissions client-side. The
// /analysis page's 댓글 tab reads from here.

import { useEffect, useState } from "react";

const COMMENT_KEY = "kestrel:comment-history";
const MAX_ENTRIES = 100;

export interface CommentHistoryEntry {
  id: number;        // backend comment id
  timestamp: number; // epoch ms
  // Exactly one of these is set — comments are attached to a post OR a CVE.
  postId?: number;
  vulnerabilityId?: string;
  // The CVE-ID string (CVE-YYYY-NNNN) when known — populated for CVE-attached
  // comments and for post comments where the post links a CVE.
  cveId?: string;
  // Excerpt of the comment body for display in the tab.
  excerpt: string;
}

export function readCommentHistory(): CommentHistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(COMMENT_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((e): e is CommentHistoryEntry =>
      e && typeof e.id === "number" && typeof e.timestamp === "number" && typeof e.excerpt === "string",
    ) : [];
  } catch {
    return [];
  }
}

export function recordCommentHistory(entry: Omit<CommentHistoryEntry, "timestamp"> & { timestamp?: number }): void {
  if (typeof window === "undefined") return;
  const existing = readCommentHistory();
  // Dedupe by comment id (same comment edited/re-submitted keeps one row).
  const filtered = existing.filter((e) => e.id !== entry.id);
  const next: CommentHistoryEntry = {
    id: entry.id,
    timestamp: entry.timestamp ?? Date.now(),
    postId: entry.postId,
    vulnerabilityId: entry.vulnerabilityId,
    cveId: entry.cveId,
    excerpt: entry.excerpt.slice(0, 240),
  };
  const merged = [next, ...filtered].slice(0, MAX_ENTRIES);
  try {
    window.localStorage.setItem(COMMENT_KEY, JSON.stringify(merged));
    window.dispatchEvent(new Event("kestrel:comment-history-changed"));
  } catch {
    /* quota — skip */
  }
}

export function deleteCommentHistory(id: number): void {
  if (typeof window === "undefined") return;
  const next = readCommentHistory().filter((e) => e.id !== id);
  window.localStorage.setItem(COMMENT_KEY, JSON.stringify(next));
  window.dispatchEvent(new Event("kestrel:comment-history-changed"));
}

export function clearCommentHistory(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(COMMENT_KEY);
  window.dispatchEvent(new Event("kestrel:comment-history-changed"));
}

export function useCommentHistory(): CommentHistoryEntry[] {
  const [entries, setEntries] = useState<CommentHistoryEntry[]>([]);
  useEffect(() => {
    const sync = () => setEntries(readCommentHistory());
    sync();
    window.addEventListener("kestrel:comment-history-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:comment-history-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  return entries;
}
