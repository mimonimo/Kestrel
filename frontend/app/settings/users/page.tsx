import type { Metadata } from "next";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";

import { AdminUsersConsole } from "@/components/settings/AdminUsersConsole";

export const metadata: Metadata = {
  title: "이용자 조회 및 감사 — Kestrel",
  description: "가입 사용자 조회·관리와 접속·활동·보안 감사 로그를 한 화면에서 확인합니다.",
};

export default function UsersAdminPage() {
  return (
    <div className="mx-auto min-h-[calc(100vh-3.5rem)] max-w-7xl px-6 py-12">
      <header className="mb-6">
        <Link
          href="/settings"
          className="mb-4 inline-flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-200"
        >
          <ChevronLeft className="h-3 w-3" /> 설정으로 돌아가기
        </Link>
        <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
          이용자 조회 및 감사
        </h1>
      </header>

      <AdminUsersConsole />
    </div>
  );
}
