"use client";

import {
  AlertCircle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  ExternalLink,
  Loader2,
  LogOut,
  ShieldAlert,
  Sparkles,
  Upload,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  ApiError,
  api,
  type AiCredential,
  type AiCredentialListResponse,
  type ClaudeAuthStart,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ErrorBox, NoticeBox } from "@/components/ui/feedback-box";
import { cn } from "@/lib/utils";

const STATUS_KEY = ["claude-auth", "status"];
const CREDS_KEY = ["ai-credentials"];
// Available models for the Claude Code CLI provider. Order = recommendation
// rank (top = best for deep analysis, bottom = fastest/cheapest).
const MODELS: { value: string; label: string; tagline: string }[] = [
  { value: "claude-opus-4-7", label: "Opus 4.7", tagline: "최고 성능 · 깊은 분석" },
  { value: "claude-sonnet-4-6", label: "Sonnet 4.6", tagline: "균형 · 일상 분석" },
  { value: "claude-haiku-4-5-20251001", label: "Haiku 4.5", tagline: "빠른 응답 · 가벼운 작업" },
];

export function ClaudeIntegrationPanel() {
  const qc = useQueryClient();

  const status = useQuery({
    queryKey: STATUS_KEY,
    queryFn: () => api.getClaudeAuthStatus(),
    staleTime: 30_000,
  });

  const credsQuery = useQuery<AiCredentialListResponse>({
    queryKey: CREDS_KEY,
    queryFn: () => api.listAiCredentials(),
    staleTime: 30_000,
  });

  // OAuth login flow state.
  const [session, setSession] = useState<ClaudeAuthStart | null>(null);
  const [code, setCode] = useState("");
  const [copied, setCopied] = useState(false);
  const [manualOpen, setManualOpen] = useState(false);
  const [manualCreds, setManualCreds] = useState("");
  const codeInputRef = useRef<HTMLInputElement | null>(null);

  const start = useMutation({
    mutationFn: () => api.startClaudeAuth(),
    onSuccess: (s) => {
      setSession(s);
      setCode("");
      try {
        window.open(s.url, "_blank", "noopener,noreferrer");
      } catch {
        /* popup blocked */
      }
      window.setTimeout(() => codeInputRef.current?.focus(), 100);
    },
  });

  const submit = useMutation({
    mutationFn: () => {
      if (!session) throw new Error("세션 없음");
      return api.submitClaudeAuthCode(session.sessionId, code.trim());
    },
    onSuccess: () => {
      setSession(null);
      setCode("");
      qc.invalidateQueries({ queryKey: STATUS_KEY });
      qc.invalidateQueries({ queryKey: CREDS_KEY });
      qc.invalidateQueries({ queryKey: ["app-settings"] });
    },
  });

  const cancel = useMutation({
    mutationFn: () => {
      if (!session) throw new Error("세션 없음");
      return api.cancelClaudeAuth(session.sessionId);
    },
    onSuccess: () => {
      setSession(null);
      setCode("");
    },
  });

  const logout = useMutation({
    mutationFn: () => api.logoutClaudeAuth(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: STATUS_KEY });
      qc.invalidateQueries({ queryKey: CREDS_KEY });
      qc.invalidateQueries({ queryKey: ["app-settings"] });
    },
  });

  const manualSave = useMutation({
    mutationFn: () => api.saveClaudeCredentials(manualCreds.trim()),
    onSuccess: () => {
      setManualCreds("");
      setManualOpen(false);
      qc.invalidateQueries({ queryKey: STATUS_KEY });
      qc.invalidateQueries({ queryKey: CREDS_KEY });
      qc.invalidateQueries({ queryKey: ["app-settings"] });
    },
  });

  // Kill session if user navigates away.
  useEffect(() => {
    return () => {
      if (session) {
        api.cancelClaudeAuth(session.sessionId).catch(() => {
          /* best-effort */
        });
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onCopyUrl = async () => {
    if (!session) return;
    try {
      await navigator.clipboard.writeText(session.url);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  // 만료 표시는 사용자 요청으로 제거. Anthropic OAuth 의 short-lived
  // access_token 은 CLI 가 refresh_token 으로 자동 갱신하므로 UI 에서
  // 카운트다운/경고/지금-갱신 버튼을 노출하는 게 오히려 혼란이었다.
  // status.loggedIn 가 곧 연동 상태. 실제 토큰 무효는 AI 호출 시점에 자연
  // surface 되며 사용자가 직접 "다시 로그인" 하면 됨.

  // The single Claude credential row (auto-created by backend on first login).
  const activeId = credsQuery.data?.activeCredentialId ?? null;
  const claudeCred = credsQuery.data?.items.find(
    (c): c is AiCredential => c.provider === "claude_cli",
  );
  const activeModel = claudeCred?.model ?? null;

  const setModel = useMutation({
    mutationFn: async (nextModel: string) => {
      if (!claudeCred) throw new Error("credential 없음");
      const updated = await api.updateAiCredential(claudeCred.id, { model: nextModel });
      // Make sure this credential is the active one.
      if (activeId !== claudeCred.id) {
        await api.activateAiCredential(claudeCred.id);
      }
      return updated;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: CREDS_KEY });
      qc.invalidateQueries({ queryKey: ["app-settings"] });
    },
  });

  if (status.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin" /> Claude 인증 상태 확인 중…
      </div>
    );
  }
  if (status.error) {
    return (
      <ErrorBox
        title="인증 상태를 확인하지 못했습니다"
        message={(status.error as Error).message}
        size="sm"
      />
    );
  }
  const data = status.data;
  if (!data) return null;

  if (!data.cliPresent) {
    return (
      <NoticeBox
        title="백엔드 이미지에 Claude Code CLI 없음"
        message="INSTALL_CLAUDE_CLI=1 (기본값) 로 백엔드 이미지를 다시 빌드해 주세요."
        hint="bash scripts/update.sh --no-pull"
      />
    );
  }


  return (
    <div className="min-w-0 space-y-5 rounded-2xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-surface-1">
      {/* ── 상단 상태 영역 ─────────────────────────────────────────────── */}
      {data.loggedIn ? (
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-emerald-500/20 text-emerald-700 ring-1 ring-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-300">
              <CheckCircle2 className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <h3 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                Claude 연동됨
              </h3>
              {data.scopes.length > 0 && (
                <p className="mt-0.5 text-[11px] text-neutral-600 dark:text-neutral-500">
                  권한: {data.scopes.join(", ")}
                </p>
              )}
            </div>
          </div>
          <Button
            size="sm"
            variant="ghost"
            disabled={logout.isPending}
            onClick={() => logout.mutate()}
            className="text-rose-700 hover:bg-rose-500/10 dark:text-rose-300"
          >
            {logout.isPending ? (
              <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
            ) : (
              <LogOut className="mr-1 h-3.5 w-3.5" />
            )}
            로그아웃
          </Button>
        </header>
      ) : (
        <header className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-amber-500/15 text-amber-700 ring-1 ring-amber-500/30 dark:text-amber-300">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
              Claude 에 아직 연결되지 않았습니다
            </h3>
            <p className="mt-0.5 text-xs text-neutral-700 dark:text-neutral-400">
              구독 계정으로 한 번만 로그인하면 됩니다. API 키 불필요.
            </p>
          </div>
        </header>
      )}

      {/* ── 진행 중 세션 ─────────────────────────────────────────────── */}
      {session && (
        <div className="min-w-0 space-y-3 overflow-hidden rounded-xl border border-sky-500/30 bg-sky-500/10 p-4 dark:bg-sky-500/5">
          <h4 className="text-sm font-semibold text-sky-900 dark:text-sky-200">
            로그인 진행 중 — 두 단계로 끝납니다
          </h4>

          <ol className="min-w-0 space-y-3 text-xs text-neutral-700 dark:text-neutral-300">
            <li className="min-w-0 space-y-2">
              <p>
                <span className="mr-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full bg-sky-500/20 text-[11px] font-semibold text-sky-800 dark:text-sky-200">
                  1
                </span>
                새 탭에서 Claude 로그인 페이지가 열렸는지 확인하고, 안 열렸다면 아래 링크를 클릭하세요. 인증 후 표시되는{" "}
                <span className="font-mono text-amber-800 dark:text-amber-200">코드</span>를 복사하세요.
              </p>
              <div className="flex min-w-0 items-center gap-2">
                <a
                  href={session.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex min-w-0 flex-1 items-center gap-1.5 overflow-hidden rounded-lg border border-sky-500/30 bg-white px-2.5 py-1.5 font-mono text-[11px] text-sky-900 hover:border-sky-400/60 dark:bg-surface-2 dark:text-sky-200"
                  title={session.url}
                >
                  <ExternalLink className="h-3 w-3 shrink-0" />
                  <span className="min-w-0 flex-1 truncate">{session.url}</span>
                </a>
                <button
                  type="button"
                  onClick={onCopyUrl}
                  className="inline-flex shrink-0 items-center gap-1 rounded-full border border-neutral-300 px-2 py-1.5 text-[11px] text-neutral-700 hover:border-neutral-400 hover:text-neutral-900 dark:border-neutral-700 dark:text-neutral-300 dark:hover:border-neutral-500 dark:hover:text-neutral-100"
                >
                  {copied ? (
                    <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                  {copied ? "복사됨" : "URL 복사"}
                </button>
              </div>
            </li>

            <li className="space-y-2">
              <p>
                <span className="mr-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full bg-sky-500/20 text-[11px] font-semibold text-sky-800 dark:text-sky-200">
                  2
                </span>
                받은 코드(<span className="font-mono">짧은문자열#긴문자열</span> 형태)를{" "}
                <span className="font-mono text-amber-800 dark:text-amber-200">전체</span>{" "}
                복사해 붙여넣고 <em>로그인 완료</em>를 누르세요.
              </p>
              <form
                className="flex items-center gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!code.trim() || submit.isPending) return;
                  submit.mutate();
                }}
              >
                <Input
                  ref={codeInputRef}
                  type="text"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="Anthropic 인증 페이지에서 받은 코드 전체"
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono"
                  disabled={submit.isPending}
                />
                <Button type="submit" size="md" disabled={!code.trim() || submit.isPending}>
                  {submit.isPending ? (
                    <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                  ) : (
                    <CheckCircle2 className="mr-1 h-4 w-4" />
                  )}
                  로그인 완료
                </Button>
                <Button
                  type="button"
                  size="md"
                  variant="ghost"
                  onClick={() => cancel.mutate()}
                  disabled={cancel.isPending}
                >
                  취소
                </Button>
              </form>
            </li>
          </ol>

          {submit.error && (
            <ErrorBox
              title="로그인 완료에 실패했습니다"
              message={
                submit.error instanceof ApiError
                  ? submit.error.message
                  : (submit.error as Error).message
              }
              size="sm"
            />
          )}
        </div>
      )}

      {/* ── 로그인 시작 버튼 (미연결 + 세션 없음일 때만) ─────────── */}
      {!session && !data.loggedIn && (
        <div className="flex flex-wrap items-center gap-3">
          <Button size="md" onClick={() => start.mutate()} disabled={start.isPending}>
            {start.isPending ? (
              <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
            ) : (
              <Sparkles className="mr-1.5 h-4 w-4" />
            )}
            Claude 로그인
          </Button>
          {start.error && (
            <span className="inline-flex items-center gap-1 text-xs text-rose-700 dark:text-rose-300">
              <AlertCircle className="h-3.5 w-3.5" />
              {(start.error as Error).message}
            </span>
          )}
        </div>
      )}

      {/* ── 모델 선택 (로그인 상태에서만 enabled) ─────────────────── */}
      <div
        className={cn(
          "rounded-xl border bg-neutral-50 p-4 dark:bg-surface-2",
          data.loggedIn
            ? "border-neutral-200 dark:border-neutral-800"
            : "border-dashed border-neutral-300 dark:border-neutral-700",
        )}
      >
        <div className="mb-3 flex items-center justify-between gap-2">
          <div>
            <h4 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              사용 모델
            </h4>
            <p className="text-[11px] text-neutral-600 dark:text-neutral-500">
              AI 심층 분석과 실습 환경 합성에서 호출되는 Claude 모델입니다.
            </p>
          </div>
          {setModel.isPending && (
            <Loader2 className="h-4 w-4 animate-spin text-sky-600 dark:text-sky-400" />
          )}
        </div>

        {!data.loggedIn ? (
          <p className="text-xs text-neutral-600 dark:text-neutral-500">
            로그인 후 모델을 선택할 수 있습니다.
          </p>
        ) : (
          <div className="grid gap-2 sm:grid-cols-3">
            {MODELS.map((m) => {
              const selected = activeModel === m.value;
              return (
                <button
                  key={m.value}
                  type="button"
                  disabled={setModel.isPending || !claudeCred}
                  onClick={() => setModel.mutate(m.value)}
                  className={cn(
                    "rounded-xl border p-3 text-left transition-all duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50",
                    selected
                      ? "border-sky-500 bg-sky-50 shadow-sm shadow-sky-500/20 dark:bg-sky-500/10"
                      : "border-neutral-200 bg-white hover:-translate-y-0.5 hover:border-neutral-300 hover:shadow-sm dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-neutral-700",
                  )}
                  aria-pressed={selected}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={cn(
                        "text-sm font-semibold",
                        selected
                          ? "text-sky-900 dark:text-sky-200"
                          : "text-neutral-900 dark:text-neutral-100",
                      )}
                    >
                      {m.label}
                    </span>
                    {selected && (
                      <Check className="h-4 w-4 text-sky-700 dark:text-sky-300" />
                    )}
                  </div>
                  <p className="mt-1 text-[11px] text-neutral-600 dark:text-neutral-500">
                    {m.tagline}
                  </p>
                </button>
              );
            })}
          </div>
        )}

        {setModel.error && (
          <p className="mt-2 text-[11px] text-rose-700 dark:text-rose-400">
            모델 변경 실패: {(setModel.error as Error).message}
          </p>
        )}
      </div>

      {/* ── 수동 자격증명 붙여넣기 (CLI 토큰 교환 실패 우회) ─────── */}
      {!data.loggedIn && !session && (
        <div className="rounded-xl border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-surface-2">
          <button
            type="button"
            onClick={() => setManualOpen((v) => !v)}
            className="flex w-full items-center justify-between gap-2 px-4 py-2.5 text-left text-xs text-neutral-600 transition-colors hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-200"
            aria-expanded={manualOpen}
          >
            <span className="inline-flex items-center gap-1.5">
              {manualOpen ? (
                <ChevronDown className="h-3.5 w-3.5" />
              ) : (
                <ChevronRight className="h-3.5 w-3.5" />
              )}
              위 흐름이 실패한다면 — 자격증명 직접 붙여넣기
            </span>
          </button>
          {manualOpen && (
            <div className="space-y-3 border-t border-neutral-200 p-4 dark:border-neutral-800">
              <ol className="list-decimal space-y-1 pl-5 text-[11px] text-neutral-700 dark:text-neutral-400">
                <li>
                  잘 동작하는 다른 환경에서 터미널을 열고{" "}
                  <code className="rounded bg-neutral-200 px-1 py-0.5 font-mono text-neutral-900 dark:bg-surface-3 dark:text-neutral-200">
                    claude setup-token
                  </code>{" "}
                  실행.
                </li>
                <li>
                  완료 후{" "}
                  <code className="rounded bg-neutral-200 px-1 py-0.5 font-mono text-neutral-900 dark:bg-surface-3 dark:text-neutral-200">
                    ~/.claude/.credentials.json
                  </code>{" "}
                  전체 내용을 복사.
                </li>
                <li>아래에 붙여넣고 "저장".</li>
              </ol>
              <textarea
                value={manualCreds}
                onChange={(e) => setManualCreds(e.target.value)}
                placeholder='{"claudeAiOauth":{"accessToken":"...","refreshToken":"...","expiresAt":...,"scopes":[...]}}'
                rows={6}
                disabled={manualSave.isPending}
                className="w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 font-mono text-[11px] text-neutral-900 placeholder:text-neutral-400 focus-visible:border-neutral-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-800 dark:bg-surface-1 dark:text-neutral-200 dark:placeholder:text-neutral-600 dark:focus-visible:border-neutral-600 dark:focus-visible:ring-neutral-600"
              />
              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  size="sm"
                  onClick={() => manualSave.mutate()}
                  disabled={!manualCreds.trim() || manualSave.isPending}
                >
                  {manualSave.isPending ? (
                    <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Upload className="mr-1 h-3.5 w-3.5" />
                  )}
                  저장
                </Button>
                <p className="text-[10px] text-neutral-600 dark:text-neutral-500">
                  한 번 저장하면 계속 유지되어 다시 입력할 필요가 없습니다.
                </p>
              </div>
              {manualSave.error && (
                <ErrorBox
                  title="자격증명 저장 실패"
                  message={
                    manualSave.error instanceof ApiError
                      ? manualSave.error.message
                      : (manualSave.error as Error).message
                  }
                  size="sm"
                />
              )}
              {manualSave.data && !manualSave.error && (
                <NoticeBox title="저장 완료" message={manualSave.data.detail} size="sm" />
              )}
            </div>
          )}
        </div>
      )}

      {/* ── 로그아웃/저장 결과 알림 ──────────────────────────────── */}
      {logout.data && !logout.error && (
        <NoticeBox title="로그아웃 완료" message={logout.data.detail} size="sm" />
      )}
      {logout.error && (
        <ErrorBox title="로그아웃 실패" message={(logout.error as Error).message} size="sm" />
      )}
    </div>
  );
}
