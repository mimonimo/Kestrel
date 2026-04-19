import Link from "next/link";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BookmarkButton } from "./BookmarkButton";
import { SeverityBadge } from "./SeverityBadge";
import { timeAgo } from "@/lib/utils";
import type { VulnerabilityListItem as Item } from "@/lib/types";

export function CveListItem({ vuln }: { vuln: Item }) {
  const osList = (vuln.osFamilies ?? []).filter((o) => o !== "other");

  return (
    <Link href={`/cve/${vuln.cveId}`} className="block">
      <Card>
        <CardHeader className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-3">
            <span className="font-mono text-sm font-semibold text-neutral-500">{vuln.cveId}</span>
            <div className="flex items-center gap-1">
              {vuln.severity && (
                <SeverityBadge severity={vuln.severity} score={vuln.cvssScore ?? undefined} />
              )}
              <BookmarkButton cveId={vuln.cveId} />
            </div>
          </div>
          <h3 className="text-base font-semibold text-neutral-100 line-clamp-2 leading-snug">
            {vuln.title}
          </h3>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <p className="text-sm text-neutral-400 line-clamp-2 leading-relaxed">
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
            {vuln.publishedAt && (
              <span className="ml-auto text-xs text-neutral-500">{timeAgo(vuln.publishedAt)}</span>
            )}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
