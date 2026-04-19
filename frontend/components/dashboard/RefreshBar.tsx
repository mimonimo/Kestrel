"use client";

import { useMemo, useState } from "react";
import { Loader2, RefreshCw } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useStatus } from "@/hooks/useStatus";
import { api } from "@/lib/api";
import { cn, timeAgo } from "@/lib/utils";
import { useUserSetting } from "@/lib/user-settings";
import type { IngestionSnapshot, Source } from "@/lib/types";

const SOURCE_LABEL: Record<Source, string> = {
  nvd: "NVD",
  exploit_db: "Exploit-DB",
  github_advisory: "GitHub Advisory",
};

function latestFinishedAt(ingestions: IngestionSnapshot[] | undefined): string | null {
  if (!ingestions || ingestions.length === 0) return null;
  const stamps = ingestions
    .map((i) => i.finishedAt)
    .filter((t): t is string => !!t)
    .sort();
  return stamps.length ? stamps[stamps.length - 1] : null;
}

export function RefreshBar() {
  const { data, refetch } = useStatus();
  const queryClient = useQueryClient();
  const { value: nvdApiKey } = useUserSetting("nvdApiKey");
  const { value: githubToken } = useUserSetting("githubToken");
  const [submitting, setSubmitting] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  const lastSync = useMemo(() => latestFinishedAt(data?.ingestions), [data?.ingestions]);

  const onRefresh = async () => {
    setSubmitting(true);
    setMsg(null);
    try {
      const res = await api.refreshIngestion({
        nvdApiKey: nvdApiKey || undefined,
        githubToken: githubToken || undefined,
      });
      const used: string[] = [];
      if (res.usedKeys.nvd) used.push("NVD key");
      if (res.usedKeys.github) used.push("GitHub token");
      setMsg({
        tone: "ok",
        text: `재수집 요청됨${used.length ? ` (${used.join(", ")} 사용)` : ""}. 곧 결과가 반영됩니다.`,
      });
      await queryClient.invalidateQueries({ queryKey: ["status"] });
      await queryClient.invalidateQueries({ queryKey: ["cve-search"] });
      await refetch();
    } catch (e) {
      setMsg({
        tone: "err",
        text: e instanceof Error ? e.message : "요청에 실패했습니다.",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-neutral-800 bg-surface-1 px-4 py-2.5 text-xs text-neutral-400">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span>
          마지막 동기화:{" "}
          <span className="font-medium text-neutral-200">
            {lastSync ? timeAgo(lastSync) : "기록 없음"}
          </span>
        </span>
        {data?.ingestions.map((ing) => (
          <span key={ing.source} className="inline-flex items-center gap-1.5">
            <span
              className={cn(
                "inline-block h-1.5 w-1.5 rounded-full",
                ing.status === "success"
                  ? "bg-emerald-400"
                  : ing.status === "failed"
                    ? "bg-amber-400"
                    : "bg-neutral-500",
              )}
            />
            <span className="text-neutral-500">{SOURCE_LABEL[ing.source]}</span>
            <span className="text-neutral-400">
              {ing.finishedAt ? timeAgo(ing.finishedAt) : "—"}
            </span>
          </span>
        ))}
      </div>
      <div className="flex items-center gap-3">
        {msg && (
          <span className={msg.tone === "ok" ? "text-emerald-400" : "text-red-400"}>
            {msg.text}
          </span>
        )}
        <button
          type="button"
          onClick={onRefresh}
          disabled={submitting}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border border-neutral-700 bg-surface-2 px-3 py-1.5 text-xs font-medium text-neutral-100 transition-colors",
            "hover:border-neutral-500 hover:bg-surface-3",
            "disabled:cursor-not-allowed disabled:opacity-60",
          )}
        >
          {submitting ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <RefreshCw className="h-3.5 w-3.5" />
          )}
          {submitting ? "수집 요청 중" : "수동 새로고침"}
        </button>
      </div>
    </div>
  );
}
