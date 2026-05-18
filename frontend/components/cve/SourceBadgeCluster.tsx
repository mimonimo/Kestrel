import type { Source } from "@/lib/types";
import { cn } from "@/lib/utils";

// Source label + tone shared across CveListItem and CveDetail. A CVE
// is now annotated with every feed that contributed data — NVD's
// enrichment, MITRE's canonical record, GitHub Advisory's package
// metadata, Exploit-DB's PoC links — so the cluster shows multiple
// chips when applicable.
const SOURCE_META: Record<Source, { label: string; cls: string; tip: string }> = {
  mitre: {
    label: "MITRE",
    cls: "border-violet-500/40 bg-violet-500/10 text-violet-800 dark:text-violet-200",
    tip: "MITRE CVE Program 의 canonical 레코드 — CVE 가 처음 publish 되는 위치",
  },
  nvd: {
    label: "NVD",
    cls: "border-sky-500/40 bg-sky-500/10 text-sky-800 dark:text-sky-200",
    tip: "NIST NVD enrichment (CPE 매칭, CVSS 보정, CWE 매핑)",
  },
  exploit_db: {
    label: "Exploit-DB",
    cls: "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-200",
    tip: "Exploit-DB 가 보유한 공개 PoC / 익스플로잇",
  },
  github_advisory: {
    label: "GHSA",
    cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200",
    tip: "GitHub Advisory — 패키지 매니저 친화적인 영향 범위 정보",
  },
};

// Stable display order regardless of how the array arrives — keeps the
// badge cluster visually consistent across rows.
const ORDER: Source[] = ["mitre", "nvd", "github_advisory", "exploit_db"];

export function SourceBadgeCluster({
  sources,
  size = "sm",
  className,
}: {
  sources: Source[] | undefined | null;
  size?: "sm" | "md";
  className?: string;
}) {
  const list = sources && sources.length > 0 ? sources : [];
  const ordered = ORDER.filter((s) => list.includes(s));
  if (ordered.length === 0) return null;
  return (
    <span className={cn("inline-flex flex-wrap items-center gap-1", className)}>
      {ordered.map((src) => {
        const m = SOURCE_META[src];
        return (
          <span
            key={src}
            title={m.tip}
            className={cn(
              "inline-flex items-center rounded border font-medium uppercase tracking-wide",
              size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-xs",
              m.cls,
            )}
          >
            {m.label}
          </span>
        );
      })}
    </span>
  );
}
