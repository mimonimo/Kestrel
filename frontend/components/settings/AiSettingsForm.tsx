"use client";

import { Check, Eye, EyeOff, Loader2, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  ApiError,
  api,
  type AiCredential,
  type AiCredentialListResponse,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

interface ProviderMeta {
  value: string;
  label: string;
  models: string[];
  defaultBaseUrl?: string;
  note?: string;
  requiresApiKey?: boolean;
}

const PROVIDERS: ProviderMeta[] = [
  {
    value: "openai",
    label: "OpenAI",
    models: [
      "gpt-5.4-nano",
      "gpt-5.4-mini",
      "gpt-5.4",
      "gpt-5.3-chat-latest",
      "gpt-5.2",
      "gpt-5.1",
      "gpt-5-mini",
      "gpt-5",
      "gpt-4o-mini",
      "gpt-4o",
      "gpt-4.1",
      "gpt-4.1-mini",
    ],
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
  {
    value: "claude_cli",
    label: "Claude Code CLI (로컬 구독)",
    models: [
      "claude-opus-4-7",
      "claude-sonnet-4-6",
      "claude-haiku-4-5-20251001",
    ],
    requiresApiKey: false,
    note:
      "별도 API 키 없이 본인 Claude Code 구독을 사용합니다. 백엔드 이미지에 claude CLI가 설치되어 있고 ~/.claude 가 마운트되어 있어야 합니다. README의 'Claude Code CLI' 섹션 참고.",
  },
  {
    value: "gemini",
    label: "Google Gemini (무료 티어)",
    defaultBaseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
    models: [
      "gemini-2.5-flash",
      "gemini-2.5-pro",
      "gemini-2.0-flash",
      "gemini-2.0-flash-lite",
      "gemini-1.5-flash",
      "gemini-1.5-pro",
    ],
    note: "aistudio.google.com에서 무료 키 발급, 일 1,500 요청(Flash) 제한",
  },
  {
    value: "groq",
    label: "Groq (무료 티어)",
    defaultBaseUrl: "https://api.groq.com/openai/v1",
    models: [
      "llama-3.3-70b-versatile",
      "llama-3.1-8b-instant",
      "mixtral-8x7b-32768",
      "gemma2-9b-it",
    ],
    note: "console.groq.com에서 키 발급, 분당 30 · 일 14,400 요청 제한",
  },
  {
    value: "openrouter",
    label: "OpenRouter (:free 모델)",
    defaultBaseUrl: "https://openrouter.ai/api/v1",
    models: [
      "deepseek/deepseek-chat-v3-0324:free",
      "google/gemini-2.0-flash-exp:free",
      "meta-llama/llama-3.3-70b-instruct:free",
      "qwen/qwen-2.5-72b-instruct:free",
    ],
    note: "openrouter.ai/keys에서 키 발급, :free 모델만 무료",
  },
  {
    value: "cerebras",
    label: "Cerebras (무료 티어)",
    defaultBaseUrl: "https://api.cerebras.ai/v1",
    models: [
      "llama-3.3-70b",
      "llama3.1-8b",
    ],
    note: "cloud.cerebras.ai에서 키 발급, 일 1M 토큰 무료",
  },
];

const DEFAULT_PROVIDER = PROVIDERS[0].value;

export function AiSettingsForm() {
  const credsQuery = useQuery<AiCredentialListResponse>({
    queryKey: ["ai-credentials"],
    queryFn: () => api.listAiCredentials(),
    staleTime: 30_000,
  });

  const items = credsQuery.data?.items ?? [];
  const activeId = credsQuery.data?.activeCredentialId ?? null;

  return (
    <div className="space-y-4">
      <CredentialList items={items} activeId={activeId} />
      <AddCredentialForm hasExisting={items.length > 0} />
    </div>
  );
}

function providerLabel(value: string): string {
  return PROVIDERS.find((p) => p.value === value)?.label ?? value;
}

function CredentialList({
  items,
  activeId,
}: {
  items: AiCredential[];
  activeId: number | null;
}) {
  const qc = useQueryClient();

  const activate = useMutation({
    mutationFn: (id: number) => api.activateAiCredential(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-credentials"] });
      qc.invalidateQueries({ queryKey: ["app-settings"] });
    },
  });

  const remove = useMutation({
    mutationFn: (id: number) => api.deleteAiCredential(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-credentials"] });
      qc.invalidateQueries({ queryKey: ["app-settings"] });
    },
  });

  const updateModel = useMutation({
    mutationFn: ({ id, model }: { id: number; model: string }) =>
      api.updateAiCredential(id, { model }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-credentials"] });
      qc.invalidateQueries({ queryKey: ["app-settings"] });
    },
  });

  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-neutral-700 bg-surface-1 p-6 text-center text-sm text-neutral-400">
        저장된 AI 키가 없습니다. 아래에서 새로 추가해주세요.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="text-xs font-medium text-neutral-300">저장된 키</div>
      <ul className="space-y-2">
        {items.map((c) => {
          const isActive = c.id === activeId;
          const busy =
            (activate.isPending && activate.variables === c.id) ||
            (remove.isPending && remove.variables === c.id);
          return (
            <li
              key={c.id}
              className={cn(
                "flex items-center justify-between gap-3 rounded-lg border p-3",
                isActive
                  ? "border-sky-500/50 bg-sky-500/10"
                  : "border-neutral-800 bg-surface-1",
              )}
            >
              <div className="flex min-w-0 flex-1 items-center gap-3">
                <input
                  type="radio"
                  name="active-credential"
                  checked={isActive}
                  disabled={busy || activate.isPending}
                  onChange={() => {
                    if (!isActive) activate.mutate(c.id);
                  }}
                  className="h-4 w-4 cursor-pointer accent-sky-500"
                  aria-label={`${c.label} 활성화`}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium text-neutral-100">
                      {c.label}
                    </span>
                    {isActive && (
                      <span className="inline-flex items-center gap-1 rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 text-[10px] font-medium text-sky-300">
                        <Check className="h-3 w-3" />
                        사용 중
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-1 gap-y-1 text-[11px] text-neutral-400">
                    <span>{providerLabel(c.provider)}</span>
                    <span>·</span>
                    <ModelSelect
                      credential={c}
                      disabled={updateModel.isPending && updateModel.variables?.id === c.id}
                      onChange={(nextModel) => {
                        if (nextModel !== c.model) {
                          updateModel.mutate({ id: c.id, model: nextModel });
                        }
                      }}
                    />
                    {updateModel.isPending && updateModel.variables?.id === c.id && (
                      <Loader2 className="h-3 w-3 animate-spin text-neutral-400" />
                    )}
                    {c.baseUrl && (
                      <>
                        <span>·</span>
                        <span className="font-mono text-neutral-500">{c.baseUrl}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                size="md"
                onClick={() => remove.mutate(c.id)}
                disabled={busy}
                className="shrink-0 text-red-400 hover:text-red-300"
                aria-label={`${c.label} 삭제`}
              >
                {remove.isPending && remove.variables === c.id ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Trash2 className="h-4 w-4" />
                )}
              </Button>
            </li>
          );
        })}
      </ul>
      {activate.isError && (
        <p className="text-xs text-red-400">
          활성화에 실패했습니다:{" "}
          {activate.error instanceof ApiError ? activate.error.message : "알 수 없는 오류"}
        </p>
      )}
      {remove.isError && (
        <p className="text-xs text-red-400">
          삭제에 실패했습니다:{" "}
          {remove.error instanceof ApiError ? remove.error.message : "알 수 없는 오류"}
        </p>
      )}
      {updateModel.isError && (
        <p className="text-xs text-red-400">
          모델 변경에 실패했습니다:{" "}
          {updateModel.error instanceof ApiError
            ? updateModel.error.message
            : "알 수 없는 오류"}
        </p>
      )}
    </div>
  );
}

function ModelSelect({
  credential,
  disabled,
  onChange,
}: {
  credential: AiCredential;
  disabled: boolean;
  onChange: (nextModel: string) => void;
}) {
  const meta = PROVIDERS.find((p) => p.value === credential.provider);
  const known = meta?.models ?? [];
  const options = known.includes(credential.model)
    ? known
    : [credential.model, ...known];
  return (
    <select
      value={credential.model}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      aria-label={`${credential.label} 모델 변경`}
      className="cursor-pointer rounded border border-neutral-800 bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-neutral-200 hover:border-neutral-600 focus:border-neutral-500 focus:outline-none disabled:cursor-wait"
    >
      {options.map((m) => (
        <option key={m} value={m}>
          {m}
        </option>
      ))}
    </select>
  );
}

function AddCredentialForm({ hasExisting }: { hasExisting: boolean }) {
  const qc = useQueryClient();

  const [label, setLabel] = useState("");
  const [provider, setProvider] = useState(DEFAULT_PROVIDER);
  const providerMeta = PROVIDERS.find((p) => p.value === provider) ?? PROVIDERS[0];
  const [model, setModel] = useState(providerMeta.models[0]);
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [activate, setActivate] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const keyRequired = providerMeta.requiresApiKey !== false;
  const create = useMutation({
    mutationFn: () =>
      api.createAiCredential({
        label: label.trim() || `${providerLabel(provider)} · ${model}`,
        provider,
        model,
        // Backend requires a non-empty api_key column; for CLI-auth providers
        // we send a harmless sentinel since the real credential lives in
        // the mounted ~/.claude directory on the server.
        apiKey: keyRequired ? apiKey : "local",
        baseUrl: baseUrl.trim() || null,
        activate: activate || !hasExisting,
      }),
    onSuccess: () => {
      setLabel("");
      setApiKey("");
      setBaseUrl(providerMeta.defaultBaseUrl ?? "");
      setShowKey(false);
      setErrorMsg(null);
      qc.invalidateQueries({ queryKey: ["ai-credentials"] });
      qc.invalidateQueries({ queryKey: ["app-settings"] });
    },
    onError: (err) => {
      setErrorMsg(err instanceof ApiError ? err.message : "저장에 실패했습니다.");
    },
  });

  const canSubmit = (!keyRequired || apiKey.trim().length > 0) && !create.isPending;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!canSubmit) return;
        create.mutate();
      }}
      className="space-y-4 rounded-lg border border-neutral-800 bg-surface-1 p-5"
    >
      <div className="flex items-center gap-2">
        <Plus className="h-4 w-4 text-neutral-400" />
        <h3 className="text-sm font-semibold text-neutral-100">새 키 추가</h3>
      </div>

      <div>
        <label className="block text-xs">
          <span className="mb-1 block font-medium text-neutral-300">
            이름 <span className="text-neutral-500">(선택, 비우면 자동 생성)</span>
          </span>
          <Input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="예: 개인 OpenAI 계정"
            maxLength={64}
          />
        </label>
      </div>

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
              setBaseUrl(meta.defaultBaseUrl ?? "");
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

      {providerMeta.note && (
        <div className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-[11px] text-sky-300">
          {providerMeta.note}
        </div>
      )}

      {keyRequired && (
        <div>
          <label className="block text-xs">
            <span className="mb-1 block font-medium text-neutral-300">
              Base URL{" "}
              <span className="text-neutral-500">
                {providerMeta.defaultBaseUrl ? "(자동 채움, 필요 시 수정)" : "(선택사항)"}
              </span>
            </span>
            <Input
              type="url"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder={providerMeta.defaultBaseUrl ?? "https://api.openai.com/v1"}
              autoComplete="off"
              spellCheck={false}
              className="font-mono"
            />
            <span className="mt-1 block text-[11px] text-neutral-500">
              OpenAI 호환 프록시나 자체 호스팅 엔드포인트를 사용할 때 입력하세요.
            </span>
          </label>
        </div>
      )}

      {keyRequired ? (
        <div>
          <div className="mb-1 flex items-center justify-between">
            <span className="text-xs font-medium text-neutral-300">API 키</span>
          </div>
          <div className="relative">
            <Input
              type={showKey ? "text" : "password"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-..."
              autoComplete="off"
              spellCheck={false}
              className="pr-10 font-mono"
              required
            />
            <button
              type="button"
              onClick={() => setShowKey((s) => !s)}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-neutral-500 hover:bg-neutral-200 hover:text-neutral-700 dark:hover:bg-surface-3 dark:hover:text-neutral-200"
              aria-label={showKey ? "값 숨기기" : "값 보기"}
            >
              {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          <p className="mt-1.5 text-[11px] text-neutral-500">
            서버 DB에 저장됩니다. 응답에는 다시 표시되지 않으므로 보관에 주의하세요.
          </p>
        </div>
      ) : (
        <div className="rounded-md border border-neutral-800 bg-surface-2 px-3 py-2 text-[11px] text-neutral-400">
          이 제공자는 API 키가 필요 없습니다. 백엔드 컨테이너의 <span className="font-mono">claude</span> CLI 로그인 정보를 사용합니다.
        </div>
      )}

      {hasExisting && (
        <label className="flex items-center gap-2 text-xs text-neutral-300">
          <input
            type="checkbox"
            checked={activate}
            onChange={(e) => setActivate(e.target.checked)}
            className="h-4 w-4 accent-sky-500"
          />
          저장 후 바로 사용하기
        </label>
      )}

      <div className="flex items-center justify-between">
        <div className="min-h-[18px] text-xs">
          {errorMsg && <span className="text-red-400">{errorMsg}</span>}
        </div>
        <Button type="submit" size="md" disabled={!canSubmit}>
          {create.isPending ? (
            <Loader2 className="mr-1 h-4 w-4 animate-spin" />
          ) : (
            <Plus className="mr-1 h-4 w-4" />
          )}
          {create.isPending ? "저장 중" : "추가"}
        </Button>
      </div>
    </form>
  );
}
