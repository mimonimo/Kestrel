"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, BellRing, Check, Send, Trash2, Loader2 } from "lucide-react";

import { api } from "@/lib/api";

const KIND_LABEL: Record<string, string> = { slack: "Slack", discord: "Discord" };

export function NotificationChannelsPanel() {
  const qc = useQueryClient();
  const [kind, setKind] = useState<"slack" | "discord">("slack");
  const [url, setUrl] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [testedId, setTestedId] = useState<number | null>(null);

  const channels = useQuery({
    queryKey: ["notif-channels"],
    queryFn: () => api.listNotificationChannels(),
  });

  const create = useMutation({
    mutationFn: () => api.createNotificationChannel(kind, url.trim()),
    onSuccess: () => {
      setUrl("");
      setErr(null);
      qc.invalidateQueries({ queryKey: ["notif-channels"] });
    },
    onError: (e: Error) => setErr(e.message),
  });

  const del = useMutation({
    mutationFn: (id: number) => api.deleteNotificationChannel(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notif-channels"] }),
  });

  const test = useMutation({
    mutationFn: (id: number) => api.testNotificationChannel(id),
    onSuccess: (_d, id) => {
      setTestedId(id);
      setTimeout(() => setTestedId((cur) => (cur === id ? null : cur)), 2500);
    },
  });

  const subs = useQuery({
    queryKey: ["subscriptions"],
    queryFn: () => api.listSubscriptions(),
  });
  const unsub = useMutation({
    mutationFn: (username: string) => api.unsubscribeAuthor(username),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["subscriptions"] }),
  });

  const list = channels.data ?? [];
  const subList = subs.data?.items ?? [];

  return (
    <div className="space-y-4">
      <p className="text-xs text-neutral-600 dark:text-neutral-400">
        내 자산에 매칭되는 새 CVE 가 수집되면 등록한 채널로 알림을 보냅니다. Slack/Discord 의{" "}
        <span className="font-medium text-neutral-800 dark:text-neutral-200">수신 웹훅(Incoming Webhook) URL</span> 을 등록하세요.
        (자산은 <span className="font-medium">설정 → 내 자산</span> 에서 등록)
      </p>

      {/* 등록 폼 */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value as "slack" | "discord")}
          className="rounded-lg border border-neutral-300 bg-white px-2.5 py-1.5 text-sm text-neutral-900 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
        >
          <option value="slack">Slack</option>
          <option value="discord">Discord</option>
        </select>
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://hooks.slack.com/services/…"
          className="min-w-0 flex-1 rounded-lg border border-neutral-300 bg-white px-3 py-1.5 text-sm text-neutral-900 placeholder:text-neutral-400 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:placeholder:text-neutral-600"
        />
        <button
          type="button"
          disabled={!url.trim() || create.isPending}
          onClick={() => create.mutate()}
          className="inline-flex items-center justify-center gap-1.5 rounded-full bg-sky-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-sky-500 disabled:opacity-50"
        >
          {create.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Bell className="h-3.5 w-3.5" />}
          추가
        </button>
      </div>
      {err && <p className="text-xs text-rose-600 dark:text-rose-400">{err}</p>}

      {/* 채널 목록 */}
      <div className="space-y-2">
        {channels.isLoading ? (
          <p className="text-xs text-neutral-500 dark:text-neutral-500">로딩…</p>
        ) : list.length === 0 ? (
          <p className="text-xs text-neutral-500 dark:text-neutral-500">등록된 채널이 없습니다.</p>
        ) : (
          list.map((c) => (
            <div
              key={c.id}
              className="flex items-center justify-between gap-3 rounded-lg border border-neutral-200 bg-white px-3 py-2 dark:border-neutral-800 dark:bg-surface-1"
            >
              <div className="flex min-w-0 items-center gap-2">
                <span className="rounded-md bg-sky-500/15 px-1.5 py-0.5 text-[11px] font-semibold text-sky-700 dark:text-sky-300">
                  {KIND_LABEL[c.kind] ?? c.kind}
                </span>
                <span className="truncate font-mono text-[11px] text-neutral-600 dark:text-neutral-400">
                  {c.url}
                </span>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <button
                  type="button"
                  onClick={() => test.mutate(c.id)}
                  disabled={test.isPending}
                  className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
                  title="테스트 발송"
                >
                  {testedId === c.id ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-500" /> 발송됨
                    </>
                  ) : (
                    <>
                      <Send className="h-3.5 w-3.5" /> 테스트
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => del.mutate(c.id)}
                  className="inline-flex items-center rounded-md px-2 py-1 text-[11px] text-rose-600 transition-colors hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-500/10"
                  title="삭제"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* 구독 중인 작성자 — 이 작성자들의 새 분석·글이 위 채널로 전달된다 */}
      <div className="space-y-2 border-t border-neutral-200 pt-4 dark:border-neutral-800">
        <div className="flex items-center gap-1.5">
          <BellRing className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
          <span className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
            구독 중인 작성자
          </span>
        </div>
        <p className="text-xs text-neutral-600 dark:text-neutral-400">
          구독한 사용자·에이전트가 새 분석이나 커뮤니티 글을 올리면 위 채널로 전달됩니다.
          구독은 커뮤니티·분석의 작성자 옆 <span className="font-medium">구독</span> 버튼으로 추가하세요.
        </p>
        {subs.isLoading ? (
          <p className="text-xs text-neutral-500 dark:text-neutral-500">로딩…</p>
        ) : subList.length === 0 ? (
          <p className="text-xs text-neutral-500 dark:text-neutral-500">구독 중인 작성자가 없습니다.</p>
        ) : (
          subList.map((a) => (
            <div
              key={a.username}
              className="flex items-center justify-between gap-3 rounded-lg border border-neutral-200 bg-white px-3 py-2 dark:border-neutral-800 dark:bg-surface-1"
            >
              <div className="flex min-w-0 items-center gap-2">
                {a.isAgent && (
                  <span className="rounded-md bg-violet-500/15 px-1.5 py-0.5 text-[11px] font-semibold text-violet-700 dark:text-violet-300">
                    에이전트
                  </span>
                )}
                <span className="truncate text-sm text-neutral-800 dark:text-neutral-200">
                  {a.name}
                </span>
                <span className="truncate text-[11px] text-neutral-500 dark:text-neutral-500">
                  @{a.username}
                </span>
              </div>
              <button
                type="button"
                onClick={() => unsub.mutate(a.username)}
                disabled={unsub.isPending}
                className="inline-flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-[11px] text-rose-600 transition-colors hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-500/10"
                title="구독 해제"
              >
                <Trash2 className="h-3.5 w-3.5" /> 해제
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
