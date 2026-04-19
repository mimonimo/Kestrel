"use client";

import { Eye, EyeOff, Loader2, Save, Trash2 } from "lucide-react";
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
            className="rounded p-1 text-neutral-500 hover:bg-surface-3 hover:text-neutral-200"
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
        <p className="text-xs text-neutral-600">아직 저장된 값이 없습니다.</p>
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
          {status === "submitting" ? "저장 중" : "저장 + 새로고침"}
        </Button>
      </form>

      {status === "saved" && (
        <p className="text-xs text-emerald-400">저장되었고, 백그라운드에서 재수집을 시작했습니다.</p>
      )}
      {status === "error" && errorMsg && (
        <p className="text-xs text-red-400">저장 또는 재수집 요청 실패: {errorMsg}</p>
      )}
    </div>
  );
}
