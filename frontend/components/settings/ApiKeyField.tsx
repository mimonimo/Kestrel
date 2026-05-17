"use client";

import { Eye, EyeOff, History, Loader2, Save, Trash2 } from "lucide-react";
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
      <div className="flex items-baseline justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-neutral-100">{meta.label}</h3>
          <p className="mt-1 text-xs text-neutral-500">{meta.help}</p>
        </div>
        <a
          href={meta.docsUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="shrink-0 text-xs text-neutral-500 underline hover:text-neutral-300"
        >
          발급받기 ↗
        </a>
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

      {ready && value && (
        <div className="flex items-center justify-between gap-3 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-200">
          <span className="text-[11px] leading-snug text-amber-200/80">
            과거 토큰 미설정/실패로 since-window 가 앞당겨져 누락분이 있을 때
            사용하세요. last_success 무시하고 처음부터 다시 가져옵니다.
          </span>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => void fullResync()}
            disabled={status === "submitting"}
            className="shrink-0 text-amber-200 hover:bg-amber-500/10"
          >
            {status === "submitting" ? (
              <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
            ) : (
              <History className="mr-1 h-3.5 w-3.5" />
            )}
            전체 다시 받기
          </Button>
        </div>
      )}

      {status === "saved" && (
        <p className="text-xs text-emerald-400">저장되었습니다. 새 키로 데이터 재수집을 백그라운드에서 시작했습니다.</p>
      )}
      {status === "error" && errorMsg && (
        <p className="text-xs text-rose-400">저장 또는 재수집 요청에 실패했습니다: {errorMsg}</p>
      )}
    </div>
  );
}
