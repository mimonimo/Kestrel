import type { Metadata } from "next";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";

import { ResourcesPanel } from "@/components/settings/ResourcesPanel";

export const metadata: Metadata = {
  title: "내부 자원 관리 — Kestrel",
  description:
    "데이터베이스 / Redis / 검색 인덱스 사용량과 점검 동작을 한 화면에서 관리합니다.",
};

export default function ResourcesPage() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-12">
      <header className="mb-8">
        <Link
          href="/settings"
          className="mb-4 inline-flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-200"
        >
          <ChevronLeft className="h-3 w-3" /> 설정으로 돌아가기
        </Link>
        <h1 className="text-2xl font-bold text-neutral-100">내부 자원 관리</h1>
        <p className="mt-1 text-sm text-neutral-500">
          데이터베이스 / Redis 캐시 / 검색 인덱스의 현재 사용량을 한 화면에서
          확인하고, 점검 동작(통계 갱신·캐시 비우기·인덱스 재구축)을 직접
          실행할 수 있습니다. 운영 중 잘못 누르면 캐시가 잠시 비어 다음 호출이
          느려지는 정도이며, 핵심 데이터(CVE 본문 등)는 영향을 받지 않습니다.
        </p>
      </header>

      <ResourcesPanel />
    </div>
  );
}
