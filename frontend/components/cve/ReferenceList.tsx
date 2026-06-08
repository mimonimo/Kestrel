"use client";

// 참고 자료 — 링크 + 서버에서 가져온 페이지 제목/요약 미리보기(나가지 않고 내용 파악).
import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";

import { api } from "@/lib/api";
import type { EnrichedRef, Reference, ReferencePreview } from "@/lib/types";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

export function ReferenceList({
  cveId,
  richRefs,
  fallbackRefs,
}: {
  cveId: string;
  richRefs: EnrichedRef[];
  fallbackRefs: Reference[];
}) {
  const refs: { url: string; tags: string[] }[] =
    richRefs.length > 0
      ? richRefs.map((r) => ({ url: r.url, tags: r.tags ?? [] }))
      : fallbackRefs.map((r) => ({ url: r.url, tags: r.type ? [r.type] : [] }));

  const previewQ = useQuery({
    queryKey: ["cve-ref-previews", cveId],
    queryFn: () => api.getReferencePreviews(cveId),
    enabled: refs.length > 0,
    staleTime: 10 * 60_000,
  });
  const byUrl = new Map<string, ReferencePreview>();
  for (const p of previewQ.data ?? []) byUrl.set(p.url, p);

  if (refs.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
          참고 자료 <span className="font-normal text-neutral-400">{refs.length}</span>
        </h2>
      </CardHeader>
      <CardContent>
        <ul className="space-y-3">
          {refs.map((ref, i) => {
            const pv = byUrl.get(ref.url);
            return (
              <li
                key={i}
                className="border-b border-neutral-100 pb-3 last:border-0 last:pb-0 dark:border-neutral-800/60"
              >
                {pv?.title && (
                  <a
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-medium text-neutral-900 hover:underline dark:text-neutral-100"
                  >
                    {pv.title}
                  </a>
                )}
                {pv?.description && (
                  <p className="mt-0.5 line-clamp-2 text-xs leading-relaxed text-neutral-600 dark:text-neutral-400">
                    {pv.description}
                  </p>
                )}
                <a
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-0.5 inline-flex items-center gap-1.5 break-all text-[11px] text-blue-400 hover:text-blue-300 hover:underline"
                >
                  {ref.url}
                  <ExternalLink className="h-3 w-3 flex-shrink-0" />
                </a>
                {ref.tags.length > 0 && (
                  <div className="mt-1 flex flex-wrap items-center gap-1.5">
                    {ref.tags.map((t) => (
                      <span
                        key={t}
                        className="rounded-full bg-sky-100 px-1.5 py-0.5 text-[10px] font-medium text-sky-800 dark:bg-sky-500/15 dark:text-sky-200"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
        {previewQ.isLoading && (
          <p className="mt-2 text-[11px] text-neutral-500">링크 내용 불러오는 중…</p>
        )}
      </CardContent>
    </Card>
  );
}
