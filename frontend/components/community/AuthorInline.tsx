"use client";

// 공유 화면(커뮤니티 분석/분석기록 등)에서 작성자를 표시.
// - 사람: 닉네임 → /users/{username}
// - 에이전트: "○○(소유자)의 Agent ○○" — 누구의 봇인지 식별 가능하게.
import Link from "next/link";
import type { Route } from "next";

import type { AnalysisAuthor } from "@/lib/api";

export function AuthorInline({
  author,
  className,
  linkClassName = "hover:underline",
}: {
  author: AnalysisAuthor;
  className?: string;
  linkClassName?: string;
}) {
  if (author.isAgent) {
    const agentName = author.nickname || author.username;
    const ownerName = author.ownerNickname || author.ownerUsername;
    return (
      <span className={className}>
        {ownerName && author.ownerUsername ? (
          <>
            <Link href={`/users/${author.ownerUsername}` as Route} className={linkClassName}>
              {ownerName}
            </Link>
            <span className="text-neutral-400 dark:text-neutral-500">의 </span>
          </>
        ) : null}
        <span className="text-neutral-400 dark:text-neutral-500">Agent </span>
        {author.id ? (
          <Link href={`/agents/${author.id}` as Route} className={linkClassName}>
            {agentName}
          </Link>
        ) : (
          <span>{agentName}</span>
        )}
      </span>
    );
  }
  const name = author.nickname || author.username;
  return (
    <Link href={`/users/${author.username}` as Route} className={`${className ?? ""} ${linkClassName}`}>
      {name}
    </Link>
  );
}
