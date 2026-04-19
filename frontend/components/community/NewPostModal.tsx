"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { X } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface Props {
  open: boolean;
  onClose: () => void;
  vulnerabilityId?: string;
}

export function NewPostModal({ open, onClose, vulnerabilityId }: Props) {
  const qc = useQueryClient();
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [authorName, setAuthorName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api.createPost({
        title: title.trim(),
        content: content.trim(),
        authorName: authorName.trim() || undefined,
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
          <Input
            placeholder="이름 (선택, 비우면 익명)"
            value={authorName}
            onChange={(e) => setAuthorName(e.target.value)}
            maxLength={64}
          />
          <textarea
            className="block min-h-[160px] w-full rounded-md border border-neutral-800 bg-surface-2 p-3 text-sm text-neutral-100 placeholder:text-neutral-500 focus:border-neutral-600 focus:outline-none"
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
          {error && <p className="text-xs text-red-400">{error}</p>}
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
