"use client";

import { ExternalLink, Eye, EyeOff, History, Loader2, Save, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { maskSecret, useUserSetting, SETTING_META, type SettingKey } from "@/lib/user-settings";

type RefreshField = "nvdApiKey" | "githubToken";

const REFRESH_HEADER_FIELD: Record<SettingKey, RefreshField> = {
  nvdApiKey: "nvdApiKey",
  githubToken: "githubToken",
};

// Per-source token for X-Full-Resync. Maps the settings key to the
// parser identifier the backend expects so the field surfaces a
// "전체 다시 받기" button bound to the right source.
const FULL_RESYNC_TOKEN: Record<SettingKey, "ghsa" | "nvd"> = {
  nvdApiKey: "nvd",
  githubToken: "ghsa",
};

export function ApiKeyField({ settingKey }: { settingKey: SettingKey }) {
  const { value, ready, save, clear } = useUserSetting(settingKey);
  const meta = SETTING_META[settingKey];
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState("");
  const [show, setShow] = useState(false);
  const [status, setStatus] = useState<"idle" | "submitting" | "saved" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (status !== "saved") return;
    const t = setTimeout(() => setStatus("idle"), 2500);
    return () => clearTimeout(t);
  }, [status]);

  const submit = async (nextValue: string) => {
    setStatus("submitting");
    setErrorMsg(null);
    try {
      save(nextValue);
      const keys: { nvdApiKey?: string; githubToken?: string } = {};
      keys[REFRESH_HEADER_FIELD[settingKey]] = nextValue;
      await api.refreshIngestion(keys);
      await queryClient.invalidateQueries({ queryKey: ["status"] });
      await queryClient.invalidateQueries({ queryKey: ["cve-search"] });
      setDraft("");
      setStatus("saved");
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : "알 수 없는 오류");
      setStatus("error");
    }
  };

  const fullResync = async () => {
    setStatus("submitting");
    setErrorMsg(null);
    try {
      const keys: { nvdApiKey?: string; githubToken?: string } = {};
      if (value) {
        keys[REFRESH_HEADER_FIELD[settingKey]] = value;
      }
      await api.refreshIngestion(keys, [FULL_RESYNC_TOKEN[settingKey]]);
      await queryClient.invalidateQueries({ queryKey: ["status"] });
      await queryClient.invalidateQueries({ queryKey: ["search", "facets"] });
      setStatus("saved");
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : "알 수 없는 오류");
      setStatus("error");
    }
  };

  const handleDelete = () => {
    clear();
    setStatus("idle");
    queryClient.invalidateQueries({ queryKey: ["status"] });
  };

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-surface-1 p-5">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-neutral-100">{meta.label}</h3>
        <div className="flex shrink-0 items-center gap-2">
          {ready && value && (
            <button
              type="button"
              onClick={() => void fullResync()}
              disabled={status === "submitting"}
              title="과거 수집 실패로 누락된 항목이 있을 때만 사용. 처음부터 다시 받아옵니다."
              className="inline-flex items-center gap-1 rounded border border-amber-500/40 px-2 py-1 text-[11px] text-amber-700 hover:border-amber-500/70 hover:bg-amber-500/10 disabled:opacity-50 dark:text-amber-300"
            >
              {status === "submitting" ? (
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
            className="inline-flex items-center gap-1 rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-400 hover:border-neutral-500 hover:text-neutral-200"
          >
            <ExternalLink className="h-3 w-3" />
            발급
          </a>
        </div>
      </div>

      {ready && value ? (
        <div className="flex items-center justify-between gap-2 rounded-md border border-neutral-800 bg-surface-2 px-3 py-2">
          <code className="flex-1 truncate font-mono text-sm text-neutral-300">
            {show ? value : maskSecret(value)}
          </code>
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            className="rounded p-1 text-neutral-500 hover:bg-neutral-200 hover:text-neutral-700 dark:hover:bg-surface-3 dark:hover:text-neutral-200"
            aria-label={show ? "값 숨기기" : "값 보기"}
          >
            {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
          <button
            type="button"
            onClick={handleDelete}
            className="flex items-center gap-1 rounded p-1 text-xs text-red-400 hover:bg-red-500/10 hover:text-red-300"
          >
            <Trash2 className="h-4 w-4" />
            <span>삭제</span>
          </button>
        </div>
      ) : (
        <p className="text-xs text-neutral-600">아직 등록된 키가 없습니다 — 비워 두어도 정상 동작합니다.</p>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!draft.trim() || status === "submitting") return;
          void submit(draft.trim());
        }}
        className="flex items-center gap-2"
      >
        <Input
          type="password"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={meta.placeholder}
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
        />
        <Button type="submit" size="md" disabled={!draft.trim() || status === "submitting"}>
          {status === "submitting" ? (
            <Loader2 className="mr-1 h-4 w-4 animate-spin" />
          ) : (
            <Save className="mr-1 h-4 w-4" />
          )}
          {status === "submitting" ? "저장 중" : "저장하고 즉시 재수집"}
        </Button>
      </form>

      {status === "saved" && (
        <p className="text-xs text-emerald-400">저장되었습니다. 새 키로 데이터 재수집을 백그라운드에서 시작했습니다.</p>
      )}
      {status === "error" && errorMsg && (
        <p className="text-xs text-rose-400">저장 또는 재수집 요청에 실패했습니다: {errorMsg}</p>
      )}
    </div>
  );
}
