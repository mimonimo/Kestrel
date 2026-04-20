import type { VulnerabilityListItem } from "./types";

export type SortKey = "newest" | "oldest" | "severity" | "cvss";

export const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: "newest", label: "최신순" },
  { value: "oldest", label: "오래된순" },
  { value: "severity", label: "심각도순" },
  { value: "cvss", label: "CVSS 점수순" },
];

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

export function sortVulnerabilities<T extends VulnerabilityListItem>(
  items: T[],
  key: SortKey,
): T[] {
  const arr = [...items];
  switch (key) {
    case "oldest":
      return arr.sort((a, b) => ts(a.publishedAt) - ts(b.publishedAt));
    case "severity":
      return arr.sort(
        (a, b) =>
          (SEVERITY_RANK[(b.severity ?? "unknown") as string] ?? 0) -
          (SEVERITY_RANK[(a.severity ?? "unknown") as string] ?? 0),
      );
    case "cvss":
      return arr.sort((a, b) => (b.cvssScore ?? -1) - (a.cvssScore ?? -1));
    case "newest":
    default:
      return arr.sort((a, b) => ts(b.publishedAt) - ts(a.publishedAt));
  }
}

function ts(s: string | null | undefined): number {
  if (!s) return 0;
  const t = new Date(s).getTime();
  return Number.isFinite(t) ? t : 0;
}
