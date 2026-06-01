"use client";

import { Suspense } from "react";
import Link from "next/link";
import type { Route } from "next";
import { ListFilter } from "lucide-react";

import { RefreshBar } from "@/components/dashboard/RefreshBar";
import { VulnDistributionPanel } from "@/components/dashboard/VulnDistributionPanel";
import { CveListSkeleton } from "@/components/cve/CveListSkeleton";
import { TimelinePanel } from "@/components/widgets/TimelinePanel";
import { TopVendorsPanel } from "@/components/widgets/TopVendorsPanel";
import { CvssBucketsPanel } from "@/components/widgets/CvssBucketsPanel";
import { RecentCriticalPanel } from "@/components/widgets/RecentCriticalPanel";
import { PriorityOverviewPanel } from "@/components/widgets/PriorityOverviewPanel";

// 메인 대시보드 — 용도: 한눈에 보는 시각화 + 수집 상태.
// 키워드 검색·세부 필터·CVE 리스트는 전부 `/cves` 탭으로 옮겨 책임이
// 명확히 분리됩니다. 여기서는 우측 상단 "취약점 조회로 이동" 버튼이
// 유일한 진입점.
function Dashboard() {
  return (
    <div className="mx-auto max-w-7xl px-6">
      <section className="pt-8 pb-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <div>
            <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">
              대시보드
            </h1>
            <p className="mt-1 text-xs text-neutral-600 dark:text-neutral-500">
              수집 현황과 위협 추세를 한눈에. 키워드·세부 필터로 좁혀 보려면 상단의
              <span className="font-medium text-neutral-800 dark:text-neutral-300">
                {" "}취약점 조회{" "}
              </span>
              탭을 이용해 주세요.
            </p>
          </div>
          <Link
            href={"/cves" as Route}
            className="inline-flex items-center gap-1.5 rounded-full border border-neutral-300 bg-white px-3 py-1.5 text-xs font-medium text-neutral-700 transition-colors hover:border-sky-400 hover:text-sky-700 dark:border-neutral-700 dark:bg-surface-1 dark:text-neutral-300 dark:hover:border-sky-500/60 dark:hover:text-sky-200"
          >
            <ListFilter className="h-3.5 w-3.5" />
            취약점 조회로 이동
          </Link>
        </div>
      </section>

      <div className="mb-6">
        <RefreshBar />
      </div>

      <VulnDistributionPanel />

      {/* Supporting visualizations — each widget is self-contained
          (own data fetch, own loader). The layout is just a CSS grid so
          adding a new widget later is "drop a component into the grid";
          nothing higher-level needs to know about it. */}
      {/* items-start: 카드가 같은 줄 최장 위젯(RecentCritical) 높이에 맞춰
          stretch 되어 CVSS·TopVendors 아래가 비던 문제 방지 — 각 카드는 자기
          콘텐츠 높이만 차지. */}
      <section className="mb-8 grid items-start gap-5 lg:grid-cols-3">
        <TopVendorsPanel />
        <CvssBucketsPanel />
        <RecentCriticalPanel />
        {/* 신규 CVE 추이 — CVSS 점수 분포 등 요약 위젯 줄 아래에 전체 폭으로.
            추세 그래프는 좌→우로 길게 읽는 게 자연스러워 한 줄 차지가 맞다. */}
        <div className="lg:col-span-3">
          <TimelinePanel />
        </div>
      </section>

      {/* Compact "어디부터 고칠 것인가" — CVSS/EPSS/KEV chips + a
          ranked 4-tier list. Sits at the bottom so the at-a-glance
          numbers above stay visible without scrolling. */}
      <section className="mb-10">
        <PriorityOverviewPanel />
      </section>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense
      fallback={
        <div className="mx-auto max-w-7xl px-6 py-16">
          <CveListSkeleton />
        </div>
      }
    >
      <Dashboard />
    </Suspense>
  );
}
