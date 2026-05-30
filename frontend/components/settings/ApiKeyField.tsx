"use client";

/**
 * 외부 데이터 소스 키 관리 — admin 전용 (PR 10-CQ).
 *
 * 이전엔 localStorage 기반이라 admin 본인 브라우저에서만 보였는데, 이제
 * backend `/admin/external-keys` 로 통합. 응답은 마스킹된 값만 (`****1234`)
 * 이라 평문은 절대 브라우저로 내려오지 않는다. 등록·삭제는 PUT 으로.
 *
 * UI 흐름:
 *  - 등록된 키가 있으면 마스킹 표시 + 삭제 버튼
 *  - 새 값 입력 → "저장하고 즉시 재수집" → PUT + POST /admin/refresh
 *  - "전체 다시 받기" 는 등록된 키로 since-window 무시 재수집
 */
import { ExternalLink, History, Loader2, Save, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SETTING_META, type SettingKey } from "@/lib/user-settings";

const FULL_RESYNC_TOKEN: Record<SettingKey, "ghsa" | "nvd"> = {
  nvdApiKey: "nvd",
  githubToken: "ghsa",
};

export function ApiKeyField({ settingKey }: { settingKey: SettingKey }) {
  const meta = SETTING_META[settingKey];
  const qc = useQueryClient();

  const list = useQuery({
    queryKey: ["admin-external-keys"],
    queryFn: () => api.getExternalKeys(),
    staleTime: 30_000,
  });
  const masked = settingKey === "nvdApiKey" ? list.data?.nvdApiKey : list.data?.githubToken;
  const isSet = settingKey === "nvdApiKey" ? list.data?.nvdSet : list.data?.githubSet;

  const [draft, setDraft] = useState("");
  const [status, setStatus] = useState<"idle" | "submitting" | "saved" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (status !== "saved") return;
    const t = setTimeout(() => setStatus("idle"), 2500);
    return () => clearTimeout(t);
  }, [status]);

  const saveAndRefresh = useMutation({
    mutationFn: async (newValue: string) => {
      // 1) DB 저장 (마스킹 응답만 반환)
      await api.putExternalKeys({ [settingKey]: newValue });
      // 2) 그 키로 즉시 재수집 트리거
      await api.refreshIngestion({ [settingKey]: newValue });
    },
    onSuccess: () => {
      setDraft("");
      setStatus("saved");
      qc.invalidateQueries({ queryKey: ["admin-external-keys"] });
      qc.invalidateQueries({ queryKey: ["status"] });
    },
    onError: (e) => {
      setErrorMsg(e instanceof Error ? e.message : "알 수 없는 오류");
      setStatus("error");
    },
  });

  const fullResync = useMutation({
    mutationFn: async () => {
      // 저장된 키를 그대로 사용 (backend 가 DB 에서 읽음 — body 안 보내도 됨)
      await api.refreshIngestion({}, [FULL_RESYNC_TOKEN[settingKey]]);
    },
    onSuccess: () => {
      setStatus("saved");
      qc.invalidateQueries({ queryKey: ["status"] });
    },
    onError: (e) => {
      setErrorMsg(e instanceof Error ? e.message : "알 수 없는 오류");
      setStatus("error");
    },
  });

  const remove = useMutation({
    mutationFn: () => api.putExternalKeys({ [settingKey]: "" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-external-keys"] });
      setStatus("idle");
    },
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft.trim() || saveAndRefresh.isPending) return;
    setStatus("submitting");
    setErrorMsg(null);
    saveAndRefresh.mutate(draft.trim());
  };

  return (
    <div className="space-y-3 rounded-lg border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">{meta.label}</h3>
        <div className="flex shrink-0 items-center gap-2">
          {isSet && (
            <button
              type="button"
              onClick={() => {
                setStatus("submitting");
                setErrorMsg(null);
                fullResync.mutate();
              }}
              disabled={fullResync.isPending}
              title="과거 수집 실패로 누락된 항목이 있을 때만 사용. 처음부터 다시 받아옵니다."
              className="inline-flex items-center gap-1 rounded border border-amber-500/40 px-2 py-1 text-[11px] text-amber-700 hover:border-amber-500/70 hover:bg-amber-500/10 disabled:opacity-50 dark:text-amber-300"
            >
              {fullResync.isPending ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <History className="h-3 w-3" />
              )}
              전체 다시 받기
            </button>
          )}
          <a
            href={meta.docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-full border border-neutral-300 px-2 py-1 text-[11px] text-neutral-700 hover:border-neutral-400 hover:text-neutral-900 dark:border-neutral-700 dark:text-neutral-400 dark:hover:border-neutral-500 dark:hover:text-neutral-200"
          >
            <ExternalLink className="h-3 w-3" />
            발급
          </a>
        </div>
      </div>

      {list.isPending ? (
        <p className="text-xs text-neutral-600 dark:text-neutral-500">불러오는 중…</p>
      ) : isSet && masked ? (
        <div className="flex items-center justify-between gap-2 rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 dark:border-neutral-800 dark:bg-surface-2">
          <code className="flex-1 truncate font-mono text-sm text-neutral-900 dark:text-neutral-300">
            {masked}
          </code>
          <span className="text-[10px] text-neutral-500 dark:text-neutral-500">서버 저장됨</span>
          <button
            type="button"
            onClick={() => {
              if (confirm("이 키를 삭제할까요? 저장된 다른 admin 세션에도 영향이 갑니다.")) {
                remove.mutate();
              }
            }}
            disabled={remove.isPending}
            className="flex items-center gap-1 rounded p-1 text-xs text-red-700 hover:bg-red-500/10 hover:text-red-800 disabled:opacity-50 dark:text-red-400 dark:hover:text-red-300"
          >
            <Trash2 className="h-4 w-4" />
            <span>삭제</span>
          </button>
        </div>
      ) : (
        <p className="text-xs text-neutral-600 dark:text-neutral-500">
          아직 등록된 키가 없습니다 — 비워 두어도 정상 동작합니다.
        </p>
      )}

      <form onSubmit={onSubmit} className="flex items-center gap-2">
        <Input
          type="password"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={meta.placeholder}
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
        />
        <Button type="submit" size="md" disabled={!draft.trim() || saveAndRefresh.isPending}>
          {saveAndRefresh.isPending ? (
            <Loader2 className="mr-1 h-4 w-4 animate-spin" />
          ) : (
            <Save className="mr-1 h-4 w-4" />
          )}
          {saveAndRefresh.isPending ? "저장 중" : "저장하고 즉시 재수집"}
        </Button>
      </form>

      {status === "saved" && (
        <p className="text-xs text-emerald-700 dark:text-emerald-400">
          저장되었습니다. 새 키로 데이터 재수집을 백그라운드에서 시작했습니다.
        </p>
      )}
      {status === "error" && errorMsg && (
        <p className="text-xs text-rose-700 dark:text-rose-400">
          저장 또는 재수집 요청에 실패했습니다: {errorMsg}
        </p>
      )}
    </div>
  );
}
