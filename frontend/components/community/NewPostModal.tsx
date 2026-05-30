"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { User as UserIcon, X } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface Props {
  open: boolean;
  onClose: () => void;
  vulnerabilityId?: string;
}

export function NewPostModal({ open, onClose, vulnerabilityId }: Props) {
  const qc = useQueryClient();
  const { user } = useAuth();
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);

  // 표시명 — 닉네임 우선, 없으면 사용자명. 백엔드도 같은 규칙으로 강제하지만
  // UX 측면에서 미리 보여 줘 "내 이름으로 게시된다"는 점을 명확히 한다.
  const displayName = (user?.nickname || user?.username || "").trim();

  const create = useMutation({
    mutationFn: () =>
      api.createPost({
        title: title.trim(),
        content: content.trim(),
        vulnerabilityId,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["community-posts"] });
      setTitle("");
      setContent("");
      setError(null);
      onClose();
    },
    onError: (err) => {
      setError(err instanceof ApiError ? err.message : "글 작성에 실패했습니다.");
    },
  });

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-xl rounded-lg border border-neutral-800 bg-surface-1 p-6 shadow-xl">
        <div className="mb-4 flex items-start justify-between">
          <h2 className="text-lg font-semibold text-neutral-100">새 글 작성</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-neutral-500 hover:bg-neutral-800 hover:text-neutral-200"
            aria-label="닫기"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!title.trim() || !content.trim()) {
              setError("제목과 본문을 입력해주세요.");
              return;
            }
            create.mutate();
          }}
          className="space-y-3"
        >
          <Input
            placeholder="제목"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            maxLength={255}
            required
          />
          <div className="flex items-center gap-2 rounded-lg border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-700 dark:border-neutral-800 dark:bg-surface-2 dark:text-neutral-300">
            <UserIcon className="h-3.5 w-3.5 text-neutral-500" />
            <span className="text-neutral-500 dark:text-neutral-500">작성자</span>
            <span className="font-medium text-neutral-900 dark:text-neutral-100">{displayName}</span>
          </div>
          <textarea
            className="block min-h-[160px] w-full rounded-lg border border-neutral-800 bg-surface-2 p-3 text-sm text-neutral-100 placeholder:text-neutral-500 focus:border-neutral-600 focus:outline-none"
            placeholder="본문 (마크다운은 지원하지 않습니다)"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            maxLength={20000}
            required
          />
          {vulnerabilityId && (
            <p className="text-xs text-neutral-500">
              이 CVE에 연결되어 게시됩니다.
            </p>
          )}
          {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={onClose} disabled={create.isPending}>
              취소
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "게시 중..." : "게시"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
