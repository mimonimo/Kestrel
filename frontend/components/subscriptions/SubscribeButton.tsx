"use client";

import { Bell, BellRing, Loader2 } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type SubscriptionsResponse } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

interface Props {
  /** 구독 대상 작성자 username. 없으면(익명 글 등) 버튼을 렌더하지 않음. */
  username?: string | null;
  /** 본인 글이면 숨김 — 자기 자신은 구독 불가. */
  hidden?: boolean;
  className?: string;
}

/**
 * 작성자 구독 토글. 대시보드 SearchBar 등과 같은 파스텔/pill 톤을 따라
 * 커뮤니티 피드·분석 카드의 작성자명 옆에 자연스럽게 얹히도록 작게 만든다.
 * 구독 상태는 ["subscriptions"] 목록 쿼리로 판단하고, 토글은 낙관적 반영 후 정합화.
 */
export function SubscribeButton({ username, hidden, className }: Props) {
  const { user } = useAuth();
  const qc = useQueryClient();

  const { data } = useQuery({
    queryKey: ["subscriptions"],
    queryFn: () => api.listSubscriptions(),
    // 비로그인이면 조회하지 않음(401 방지). 로그인 시에만 활성.
    enabled: !!user,
    staleTime: 30_000,
  });
  const subscribed = !!data?.items.some((a) => a.username === username);

  const mutation = useMutation({
    mutationFn: async (next: boolean) =>
      next ? api.subscribeAuthor(username!) : api.unsubscribeAuthor(username!),
    onMutate: async (next) => {
      await qc.cancelQueries({ queryKey: ["subscriptions"] });
      const prev = qc.getQueryData<SubscriptionsResponse>(["subscriptions"]);
      if (prev && username) {
        qc.setQueryData<SubscriptionsResponse>(["subscriptions"], {
          items: next
            ? [...prev.items, { username, name: username, isAgent: false }]
            : prev.items.filter((a) => a.username !== username),
        });
      }
      return { prev };
    },
    onError: (_e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(["subscriptions"], ctx.prev);
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["subscriptions"] }),
  });

  if (!username || hidden) return null;

  const onClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    if (!user) {
      if (typeof window !== "undefined") {
        const next = window.location.pathname + window.location.search;
        window.location.href = `/login?next=${encodeURIComponent(next)}`;
      }
      return;
    }
    mutation.mutate(!subscribed);
  };

  const busy = mutation.isPending;
  const Icon = busy ? Loader2 : subscribed ? BellRing : Bell;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={subscribed}
      title={subscribed ? "구독 중 — 새 분석·글을 알림채널로 받아요" : "이 작성자의 새 분석·글을 알림채널로 받기"}
      className={cn(
        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset transition-colors",
        subscribed
          ? "bg-sky-50 text-sky-700 ring-sky-200 hover:bg-sky-100 dark:bg-sky-500/10 dark:text-sky-300 dark:ring-sky-500/30 dark:hover:bg-sky-500/20"
          : "bg-surface-2 text-neutral-600 ring-neutral-200 hover:text-neutral-900 dark:text-neutral-400 dark:ring-neutral-700 dark:hover:text-neutral-100",
        className,
      )}
    >
      <Icon className={cn("h-3 w-3", busy && "animate-spin")} />
      {subscribed ? "구독 중" : "구독"}
    </button>
  );
}
