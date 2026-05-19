import Link from "next/link";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BookmarkButton } from "./BookmarkButton";
import { SeverityBadge } from "./SeverityBadge";
import { SourceBadgeCluster } from "./SourceBadgeCluster";
import { TicketBadge } from "./TicketBadge";
import { timeAgo } from "@/lib/utils";
import type { VulnerabilityListItem as Item } from "@/lib/types";

export function CveListItem({ vuln }: { vuln: Item }) {
  const osList = (vuln.osFamilies ?? []).filter((o) => o !== "other");

  return (
    <Link href={`/cve/${vuln.cveId}`} className="block">
      <Card>
        <CardHeader className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-3">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-semibold text-neutral-600 dark:text-neutral-500">
                {vuln.cveId}
              </span>
              <SourceBadgeCluster sources={vuln.sources ?? [vuln.source]} />
              <TicketBadge cveId={vuln.cveId} />
            </div>
            <div className="flex items-center gap-1">
              {vuln.severity && (
                <SeverityBadge severity={vuln.severity} score={vuln.cvssScore ?? undefined} />
              )}
              <BookmarkButton cveId={vuln.cveId} />
            </div>
          </div>
          <h3 className="line-clamp-2 text-base font-semibold leading-snug text-neutral-900 dark:text-neutral-100">
            {vuln.title}
          </h3>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <p className="line-clamp-2 text-sm leading-relaxed text-neutral-700 dark:text-neutral-400">
            {vuln.summary || "요약이 아직 생성되지 않았습니다."}
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {vuln.types.map((t) => (
              <Badge key={t} variant="secondary">
                {t}
              </Badge>
            ))}
            {osList.map((os) => (
              <Badge key={os} variant="outline" className="uppercase">
                {os}
              </Badge>
            ))}
            {(vuln.domains ?? []).map((d) => (
              <Badge
                key={d}
                variant="outline"
                className="border-cyan-300 text-cyan-700 dark:border-cyan-900/60 dark:text-cyan-300"
              >
                {d}
              </Badge>
            ))}
            {vuln.publishedAt && (
              <span className="ml-auto text-xs tabular-nums text-neutral-500 dark:text-neutral-500">
                {timeAgo(vuln.publishedAt)}
              </span>
            )}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
