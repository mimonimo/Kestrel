"use client";

import { Activity, AlertCircle, Check, Eye, EyeOff, Loader2, Plus, Trash2, X } from "lucide-react";
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

// PR 10-T: provider 매트릭스 단순화. 사용자 요청 — claude_cli 외 모두
// 제거. AI 분석/합성 의 truth oracle 이 모두 백엔드 probe 기반이라
// 모델 다변화의 의미 적고, 다중 provider 가 인증/오류 매트릭스만
// 키워 UX 가 조잡해짐. 호스트 Claude 구독 단일 경로로 정리.
const PROVIDERS: ProviderMeta[] = [
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
      "별도의 API 키 없이 본인의 Claude Code 구독을 그대로 사용합니다. 설치 시 README 의 'Claude Code CLI' 섹션을 따라 한 번만 인증해 두면 자동으로 갱신됩니다.",
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
                      <span className="inline-flex items-center gap-1 rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 text-[10px] font-medium text-sky-700 dark:text-sky-300">
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
                  {isActive && <ConnectionTest />}
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                size="md"
                onClick={() => remove.mutate(c.id)}
                disabled={busy}
                className="shrink-0 text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300"
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
        <p className="text-xs text-rose-600 dark:text-rose-400">
          활성화에 실패했습니다:{" "}
          {activate.error instanceof ApiError ? activate.error.message : "알 수 없는 오류"}
        </p>
      )}
      {remove.isError && (
        <p className="text-xs text-rose-600 dark:text-rose-400">
          삭제에 실패했습니다:{" "}
          {remove.error instanceof ApiError ? remove.error.message : "알 수 없는 오류"}
        </p>
      )}
      {updateModel.isError && (
        <p className="text-xs text-rose-600 dark:text-rose-400">
          모델 변경에 실패했습니다:{" "}
          {updateModel.error instanceof ApiError
            ? updateModel.error.message
            : "알 수 없는 오류"}
        </p>
      )}
    </div>
  );
}

// Connection-test button + inline result. Only renders for the active
// credential row — testing inactive ones doesn't make sense (only the
// active one drives AI 분석/sandbox synth). Surface errors with
// kind-specific remediation so users immediately see "왜 안 되나".
function ConnectionTest() {
  const [result, setResult] = useState<
    | { ok: true; latencyMs: number; preview: string | null; cliVersion: string | null }
    | { ok: false; kind: string | null; detail: string | null; cliVersion: string | null }
    | null
  >(null);
  const ping = useMutation({
    mutationFn: () => api.pingActiveCredential(),
    onSuccess: (r) => {
      if (r.ok) {
        setResult({
          ok: true,
          latencyMs: r.latencyMs,
          preview: r.replyPreview,
          cliVersion: r.cliVersion,
        });
      } else {
        setResult({
          ok: false,
          kind: r.errorKind,
          detail: r.errorDetail,
          cliVersion: r.cliVersion,
        });
      }
    },
    onError: (e: Error) => {
      setResult({ ok: false, kind: "unknown", detail: e.message, cliVersion: null });
    },
  });

  const hint = result && !result.ok
    ? remedyForKind(result.kind)
    : null;

  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      <Button
        type="button"
        variant="outline"
        size="md"
        onClick={() => ping.mutate()}
        disabled={ping.isPending}
        className="gap-1"
      >
        {ping.isPending ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Activity className="h-3.5 w-3.5" />
        )}
        연결 테스트
      </Button>
      {result?.ok && (
        <span className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-300">
          <Check className="h-3 w-3" />
          OK · {result.latencyMs}ms
          {result.cliVersion && <span className="text-emerald-700 dark:text-emerald-300/70">· {result.cliVersion}</span>}
        </span>
      )}
      {result && !result.ok && (
        <span className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-[11px] text-rose-700 dark:text-rose-300">
          <X className="h-3 w-3" />
          {labelForKind(result.kind)}
          {result.cliVersion && <span className="text-rose-700 dark:text-rose-300/70">· {result.cliVersion}</span>}
        </span>
      )}
      {hint && (
        <p className="basis-full text-[11px] leading-relaxed text-rose-800 dark:text-rose-200/90">
          <AlertCircle className="mr-1 inline h-3 w-3" />
          {hint}
        </p>
      )}
      {result && !result.ok && result.detail && (
        <p className="basis-full break-words text-[10px] text-neutral-500">
          상세: {result.detail.slice(0, 240)}
        </p>
      )}
    </div>
  );
}


function labelForKind(kind: string | null): string {
  switch (kind) {
    case "auth_expired":
      return "인증 만료";
    case "rate_limit":
      return "사용량 한도";
    case "not_logged_in":
      return "로그인 안 됨";
    case "config_missing":
      return "설정 파일 없음";
    case "cli_missing":
      return "CLI 미설치";
    case "empty_response":
      return "빈 응답";
    case "not_configured":
      return "활성 키 없음";
    default:
      return "오류";
  }
}


function remedyForKind(kind: string | null): string | null {
  switch (kind) {
    case "auth_expired":
    case "not_logged_in":
      return "Claude 인증이 만료되었습니다. 호스트 터미널에서 `bash backend/scripts/refresh_and_sync_claude_creds.sh` 를 한 번 실행하면 갱신됩니다 (매시간 자동 갱신되지만 만료 직후에는 수동 갱신이 필요할 수 있습니다).";
    case "rate_limit":
      return "Claude 구독 사용량 한도에 도달했습니다. 표시된 reset 시각 이후 다시 시도하거나, 별도 키를 등록해 활성화해 주세요.";
    case "config_missing":
      return "Claude 인증 파일이 백엔드와 연결되지 않았습니다. 백엔드 컨테이너를 한 번 재시작하면 해결됩니다.";
    case "cli_missing":
      return "백엔드 이미지에 Claude CLI 가 설치되어 있지 않습니다. README 설치 가이드의 'AI 키 등록' 단계를 다시 진행해 주세요.";
    case "empty_response":
      return "Claude 가 응답 없이 종료되었습니다. 자동 복구가 실패했다면 인증 토큰이 만료되었을 가능성이 큽니다 — 위 인증 갱신 안내를 따라 주세요.";
    case "not_configured":
      return "현재 활성화된 AI 키가 없습니다. 아래에서 키를 추가하고 라디오 버튼으로 활성화해 주세요.";
    default:
      return null;
  }
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
            placeholder="예: 메인 Claude 구독"
            maxLength={64}
          />
        </label>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {PROVIDERS.length > 1 ? (
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
        ) : (
          // PR 10-T 후 provider 가 1개 (claude_cli) 뿐이라 dropdown 의미
          // 없음. 정적 라벨로 표시 — sandbox provider 매트릭스 단순화의
          // 시각적 반영.
          <div className="block text-xs">
            <span className="mb-1 block font-medium text-neutral-300">AI 제공자</span>
            <div className="flex h-[42px] w-full items-center rounded-md border border-neutral-800 bg-surface-2 px-3 text-sm text-neutral-100">
              {providerMeta.label}
            </div>
          </div>
        )}

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
        <div className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-[11px] text-sky-700 dark:text-sky-300">
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
              placeholder={providerMeta.defaultBaseUrl ?? "https://example.com/v1"}
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
            키는 안전하게 저장되며, 한번 등록 후에는 화면에 다시 표시되지 않으니
            원본은 별도로 보관해 주세요.
          </p>
        </div>
      ) : (
        <div className="rounded-md border border-neutral-800 bg-surface-2 px-3 py-2 text-[11px] text-neutral-400">
          이 제공자는 별도 API 키가 필요 없습니다. 호스트에 로그인된 Claude
          구독 자격 증명을 그대로 사용합니다.
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
          {errorMsg && <span className="text-rose-600 dark:text-rose-400">{errorMsg}</span>}
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
