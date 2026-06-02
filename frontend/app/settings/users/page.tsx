import type { Metadata } from "next";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";

import { UserManagementPanel } from "@/components/settings/UserManagementPanel";
import { AuditLogPanel } from "@/components/settings/AuditLogPanel";

export const metadata: Metadata = {
  title: "이용자 조회 및 감사 — Kestrel",
  description: "가입 사용자 조회·관리와 보안 감사 로그를 한 화면에서 확인합니다.",
};

export default function UsersAdminPage() {
  return (
    <div className="mx-auto min-h-[calc(100vh-3.5rem)] max-w-7xl px-6 py-12">
      <header className="mb-8">
        <Link
          href="/settings"
          className="mb-4 inline-flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-200"
        >
          <ChevronLeft className="h-3 w-3" /> 설정으로 돌아가기
        </Link>
        <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
          이용자 조회 및 감사
        </h1>
        <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-500">
          가입한 사용자의 활동·접속 기록을 조회하고 계정을 관리합니다. 아래 감사 로그에서는
          로그인·가입·권한 변경 등 보안 이벤트 이력을 확인할 수 있습니다.
        </p>
      </header>

      <div className="space-y-10">
        <section className="space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-600 dark:text-neutral-400">
            이용자 조회 및 관리
          </h2>
          <UserManagementPanel />
        </section>

        <section className="space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-600 dark:text-neutral-400">
            로깅 감사
          </h2>
          <AuditLogPanel />
        </section>
      </div>
    </div>
  );
}
