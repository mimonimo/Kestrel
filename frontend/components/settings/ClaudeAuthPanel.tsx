"use client";

import {
  AlertCircle,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  Loader2,
  LogOut,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, api, type ClaudeAuthStart } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ErrorBox, NoticeBox } from "@/components/ui/feedback-box";
import { cn } from "@/lib/utils";

const STATUS_KEY = ["claude-auth", "status"];

function formatExpires(epochSeconds: number | null): string {
  if (!epochSeconds) return "정보 없음";
  const d = new Date(epochSeconds * 1000);
  const diffMs = d.getTime() - Date.now();
  const days = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (diffMs < 0) return `${stamp} (만료됨)`;
  if (days > 30) return `${stamp} (장기 토큰)`;
  if (days > 0) return `${stamp} (${days}일 후 만료)`;
  const hours = Math.floor(diffMs / (60 * 60 * 1000));
  return `${stamp} (${hours}시간 후 만료)`;
}

export function ClaudeAuthPanel() {
  const qc = useQueryClient();
  const status = useQuery({
    queryKey: STATUS_KEY,
    queryFn: () => api.getClaudeAuthStatus(),
    staleTime: 30_000,
  });

  // Local state for the in-progress login flow.
  const [session, setSession] = useState<ClaudeAuthStart | null>(null);
  const [code, setCode] = useState("");
  const [copied, setCopied] = useState(false);
  const codeInputRef = useRef<HTMLInputElement | null>(null);

  const start = useMutation({
    mutationFn: () => api.startClaudeAuth(),
    onSuccess: (s) => {
      setSession(s);
      setCode("");
      // Auto-open the URL in a new tab — most users want this.
      try {
        window.open(s.url, "_blank", "noopener,noreferrer");
      } catch {
        /* popup blocked — user can click the URL chip instead */
      }
      // Focus the code field so paste-and-submit is one motion.
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
    onSuccess: () => qc.invalidateQueries({ queryKey: STATUS_KEY }),
  });

  // If user navigates away while a session is open, kill it server-side
  // so the subprocess + PTY get cleaned up.
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

  if (status.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-500">
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

  // CLI not installed in image — explain instead of letting user click into a 503.
  if (!data.cliPresent) {
    return (
      <NoticeBox
        title="이 백엔드 이미지에는 Claude Code CLI 가 없습니다"
        message="대시보드 로그인 흐름은 컨테이너 안의 Claude Code CLI 가 OAuth 를 처리합니다. INSTALL_CLAUDE_CLI=1 (기본값) 로 백엔드 이미지를 다시 빌드해 주세요."
        hint="bash scripts/update.sh --no-pull"
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* ── 현재 로그인 상태 ─────────────────────────────────────────── */}
      {data.loggedIn ? (
        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30">
                <CheckCircle2 className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-emerald-200">
                  Claude 에 로그인되어 있습니다
                </h3>
                <p className="mt-1 text-xs text-neutral-400">
                  자격증명 만료 시각:{" "}
                  <span className="text-neutral-200">{formatExpires(data.expiresAt)}</span>
                </p>
                {data.scopes.length > 0 && (
                  <p className="mt-1 text-[11px] text-neutral-500">
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
              className="text-rose-300 hover:bg-rose-500/10"
            >
              {logout.isPending ? (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              ) : (
                <LogOut className="mr-1 h-3.5 w-3.5" />
              )}
              로그아웃
            </Button>
          </div>
        </div>
      ) : (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-4">
          <div className="flex items-start gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30">
              <ShieldAlert className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-semibold text-amber-200">
                Claude 에 아직 로그인되어 있지 않습니다
              </h3>
              <p className="mt-1 text-xs text-neutral-400">
                AI 심층 분석과 실습 환경 합성 기능을 사용하려면 본인의 Claude
                구독으로 한 번만 로그인하면 됩니다. 별도 API 키는 필요하지
                않습니다.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ── 진행 중 세션이 없을 때: 시작 버튼 ─────────────────────── */}
      {!session && (
        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="md"
            onClick={() => start.mutate()}
            disabled={start.isPending}
          >
            {start.isPending ? (
              <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
            ) : (
              <Sparkles className="mr-1.5 h-4 w-4" />
            )}
            {data.loggedIn ? "다시 로그인" : "Claude 로그인"}
          </Button>
          {start.error && (
            <span className="inline-flex items-center gap-1 text-xs text-rose-300">
              <AlertCircle className="h-3.5 w-3.5" />
              {(start.error as Error).message}
            </span>
          )}
        </div>
      )}

      {/* ── 진행 중 세션 ─────────────────────────────────────────── */}
      {session && (
        <div className="space-y-3 rounded-md border border-sky-500/30 bg-sky-500/5 p-4">
          <h3 className="text-sm font-semibold text-sky-200">
            로그인 진행 중 — 두 단계로 끝납니다
          </h3>

          <ol className="space-y-3 text-xs text-neutral-300">
            <li className="space-y-2">
              <p>
                <span className="mr-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full bg-sky-500/20 text-[11px] font-semibold text-sky-200">
                  1
                </span>
                새 탭에서 Claude 로그인 페이지가 열렸는지 확인하고, 안 열렸다면
                아래 링크를 클릭하세요. Anthropic 인증 후 화면에 표시되는{" "}
                <span className="font-mono text-amber-200">코드</span>를 복사하세요.
              </p>
              <div className="flex items-center gap-2">
                <a
                  href={session.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex min-w-0 flex-1 items-center gap-1.5 truncate rounded border border-sky-500/30 bg-surface-2 px-2.5 py-1.5 font-mono text-[11px] text-sky-200 hover:border-sky-400/60"
                  title={session.url}
                >
                  <ExternalLink className="h-3 w-3 shrink-0" />
                  <span className="truncate">{session.url}</span>
                </a>
                <button
                  type="button"
                  onClick={onCopyUrl}
                  className="inline-flex items-center gap-1 rounded border border-neutral-700 px-2 py-1.5 text-[11px] text-neutral-300 hover:border-neutral-500 hover:text-neutral-100"
                >
                  {copied ? (
                    <Check className="h-3 w-3 text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                  {copied ? "복사됨" : "URL 복사"}
                </button>
              </div>
            </li>

            <li className="space-y-2">
              <p>
                <span className="mr-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full bg-sky-500/20 text-[11px] font-semibold text-sky-200">
                  2
                </span>
                받은 코드를 아래에 붙여넣고 <em>로그인 완료</em>를 누르세요.
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
                  placeholder="예: ory_at_..."
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono"
                  disabled={submit.isPending}
                />
                <Button
                  type="submit"
                  size="md"
                  disabled={!code.trim() || submit.isPending}
                >
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
                  className="text-neutral-400"
                >
                  취소
                </Button>
              </form>
            </li>
          </ol>

          <p className="text-[11px] text-neutral-500">
            세션은 10분 후 자동으로 만료됩니다. 자격증명은 백엔드의 영구
            저장 공간(named volume)에 저장되어 컨테이너를 재시작해도
            유지됩니다.
          </p>

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

      {/* ── 결과 알림 ─────────────────────────────────────────────── */}
      {logout.data && !logout.error && (
        <NoticeBox title="로그아웃 완료" message={logout.data.detail} size="sm" />
      )}
      {logout.error && (
        <ErrorBox
          title="로그아웃 실패"
          message={(logout.error as Error).message}
          size="sm"
        />
      )}
    </div>
  );
}
