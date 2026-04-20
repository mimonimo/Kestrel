"use client";

import { Eye, EyeOff, Loader2, Save, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, api, type AppSettingsResponse } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const PROVIDERS: { value: string; label: string; models: string[] }[] = [
  {
    value: "openai",
    label: "OpenAI",
    models: ["gpt-4o-mini", "gpt-4o", "gpt-4.1", "gpt-4.1-mini"],
  },
  {
    value: "anthropic",
    label: "Anthropic",
    models: [
      "claude-haiku-4-5-20251001",
      "claude-sonnet-4-6",
      "claude-opus-4-7",
    ],
  },
];

const DEFAULT_PROVIDER = PROVIDERS[0].value;

export function AiSettingsForm() {
  const qc = useQueryClient();
  const settingsQuery = useQuery<AppSettingsResponse>({
    queryKey: ["app-settings"],
    queryFn: () => api.getAppSettings(),
    staleTime: 30_000,
  });

  const [provider, setProvider] = useState<string>(DEFAULT_PROVIDER);
  const [model, setModel] = useState<string>("");
  const [keyDraft, setKeyDraft] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [status, setStatus] = useState<"idle" | "saved" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    const data = settingsQuery.data;
    if (!data) return;
    const p = data.aiProvider ?? DEFAULT_PROVIDER;
    setProvider(p);
    const provMeta = PROVIDERS.find((x) => x.value === p) ?? PROVIDERS[0];
    setModel(data.aiModel ?? provMeta.models[0]);
  }, [settingsQuery.data]);

  useEffect(() => {
    if (status !== "saved") return;
    const t = setTimeout(() => setStatus("idle"), 2500);
    return () => clearTimeout(t);
  }, [status]);

  const providerMeta = PROVIDERS.find((p) => p.value === provider) ?? PROVIDERS[0];

  const save = useMutation({
    mutationFn: (clearKey: boolean) =>
      api.updateAppSettings({
        aiProvider: provider,
        aiModel: model || providerMeta.models[0],
        ...(clearKey
          ? { aiApiKey: null }
          : keyDraft
            ? { aiApiKey: keyDraft }
            : {}),
      }),
    onSuccess: (data) => {
      qc.setQueryData(["app-settings"], data);
      setKeyDraft("");
      setStatus("saved");
      setErrorMsg(null);
    },
    onError: (err) => {
      setErrorMsg(err instanceof ApiError ? err.message : "저장에 실패했습니다.");
      setStatus("error");
    },
  });

  const hasKey = !!settingsQuery.data?.hasApiKey;

  return (
    <div className="space-y-4 rounded-lg border border-neutral-800 bg-surface-1 p-5">
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block text-xs">
          <span className="mb-1 block font-medium text-neutral-300">AI 제공자</span>
          <select
            value={provider}
            onChange={(e) => {
              const next = e.target.value;
              setProvider(next);
              const meta = PROVIDERS.find((p) => p.value === next) ?? PROVIDERS[0];
              setModel(meta.models[0]);
            }}
            className="w-full rounded-md border border-neutral-800 bg-surface-2 px-3 py-2 text-sm text-neutral-100 focus:border-neutral-600 focus:outline-none"
          >
            {PROVIDERS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
        </label>

        <label className="block text-xs">
          <span className="mb-1 block font-medium text-neutral-300">모델</span>
          <select
            value={model}
            onChange={(e) => setModel(e.target.value)}
            className="w-full rounded-md border border-neutral-800 bg-surface-2 px-3 py-2 text-sm text-neutral-100 focus:border-neutral-600 focus:outline-none"
          >
            {providerMeta.models.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-xs font-medium text-neutral-300">API 키</span>
          {hasKey && (
            <span className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-300">
              저장됨
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Input
              type={showKey ? "text" : "password"}
              value={keyDraft}
              onChange={(e) => setKeyDraft(e.target.value)}
              placeholder={hasKey ? "새 키로 교체하려면 입력 (비워두면 유지)" : "sk-..."}
              autoComplete="off"
              spellCheck={false}
              className="pr-10 font-mono"
            />
            <button
              type="button"
              onClick={() => setShowKey((s) => !s)}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-neutral-500 hover:bg-surface-3 hover:text-neutral-200"
              aria-label={showKey ? "값 숨기기" : "값 보기"}
            >
              {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          {hasKey && (
            <Button
              type="button"
              variant="outline"
              size="md"
              onClick={() => save.mutate(true)}
              disabled={save.isPending}
              className="text-red-400 hover:text-red-300"
            >
              <Trash2 className="mr-1 h-4 w-4" />
              키 삭제
            </Button>
          )}
        </div>
        <p className="mt-1.5 text-[11px] text-neutral-500">
          서버 DB에 저장됩니다. 응답에는 다시 표시되지 않으므로 보관에 주의하세요.
        </p>
      </div>

      <div className="flex items-center justify-between">
        <div className="min-h-[18px] text-xs">
          {status === "saved" && (
            <span className="text-emerald-400">저장되었습니다.</span>
          )}
          {status === "error" && errorMsg && (
            <span className="text-red-400">{errorMsg}</span>
          )}
        </div>
        <Button
          type="button"
          size="md"
          onClick={() => save.mutate(false)}
          disabled={save.isPending}
        >
          {save.isPending ? (
            <Loader2 className="mr-1 h-4 w-4 animate-spin" />
          ) : (
            <Save className="mr-1 h-4 w-4" />
          )}
          {save.isPending ? "저장 중" : "저장"}
        </Button>
      </div>
    </div>
  );
}
