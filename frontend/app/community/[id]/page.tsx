"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Eye, MessageSquare, Trash2 } from "lucide-react";

import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { CommentThread } from "@/components/community/CommentThread";
import { formatRelativeKo } from "@/lib/format";

export default function PostDetailPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params?.id);
  const router = useRouter();
  const qc = useQueryClient();

  const { data, isPending, isError } = useQuery({
    queryKey: ["community-post", id],
    queryFn: () => api.getPost(id),
    enabled: Number.isFinite(id),
    staleTime: 5_000,
  });

  const remove = useMutation({
    mutationFn: () => api.deletePost(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["community-posts"] });
      router.push("/community");
    },
  });

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <Link
        href="/community"
        className="mb-4 inline-flex items-center gap-1 text-sm text-neutral-500 hover:text-neutral-100"
      >
        <ArrowLeft className="h-4 w-4" />
        목록으로
      </Link>

      {isPending ? (
        <div className="h-40 animate-pulse rounded-lg border border-neutral-800 bg-surface-1/50" />
      ) : isError || !data ? (
        <div className="rounded border border-red-900/40 bg-red-950/30 p-6 text-sm text-red-300">
          글을 불러오지 못했습니다.
        </div>
      ) : (
        <article className="rounded-lg border border-neutral-800 bg-surface-1 p-6">
          <header className="mb-4 border-b border-neutral-800 pb-4">
            <h1 className="text-xl font-bold text-neutral-100">{data.title}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-neutral-500">
              <span className="font-medium text-neutral-300">{data.authorName}</span>
              <span>·</span>
              <span>{formatRelativeKo(data.createdAt)}</span>
              <span>·</span>
              <span className="inline-flex items-center gap-1">
                <Eye className="h-3 w-3" />
                {data.viewCount}
              </span>
              <span>·</span>
              <span className="inline-flex items-center gap-1">
                <MessageSquare className="h-3 w-3" />
                {data.commentCount}
              </span>
              {data.vulnerabilityId && (
                <Link
                  href={`/cve/${data.vulnerabilityId}`}
                  className="ml-auto rounded bg-blue-500/10 px-2 py-0.5 text-blue-300 hover:bg-blue-500/20"
                >
                  연결된 CVE 보기 →
                </Link>
              )}
            </div>
          </header>

          <div className="whitespace-pre-wrap break-words text-sm leading-relaxed text-neutral-200">
            {data.content}
          </div>

          {data.isOwner && (
            <div className="mt-6 flex justify-end">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  if (confirm("이 글을 삭제하시겠습니까?")) remove.mutate();
                }}
                disabled={remove.isPending}
                className="gap-1 border-red-900/50 text-red-300 hover:bg-red-950/40"
              >
                <Trash2 className="h-3.5 w-3.5" />
                삭제
              </Button>
            </div>
          )}

          <CommentThread postId={data.id} />
        </article>
      )}
    </div>
  );
}
