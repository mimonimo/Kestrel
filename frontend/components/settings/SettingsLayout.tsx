"use client";

import Link from "next/link";
import {
  ChevronRight,
  Database,
  Key,
  Lock,
  Server,
  Sparkles,
  User,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { ApiKeyField } from "@/components/settings/ApiKeyField";
import { AssetsManager } from "@/components/settings/AssetsManager";
import { ClaudeIntegrationPanel } from "@/components/settings/ClaudeIntegrationPanel";
import { MitreBackfillPanel } from "@/components/settings/MitreBackfillPanel";
import { ThemeSwitcher } from "@/components/settings/ThemeSwitcher";
import { VersionPanel } from "@/components/settings/VersionPanel";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

interface SectionDef {
  id: string;
  title: string;
  description: string;
  render: () => React.ReactNode;
}

interface CategoryDef {
  id: string;
  title: string;
  icon: typeof User;
  // 'all'   = 로그인 사용자 누구나
  // 'admin' = 관리자만 (사이드바/본문 모두 숨김)
  audience: "all" | "admin";
  sections: SectionDef[];
}

// Single source of truth — sidebar nav and the body sections both
// read from this list. Add a section here and it shows up in both.
const CATEGORIES: CategoryDef[] = [
  {
    id: "personal",
    title: "개인 설정",
    icon: User,
    audience: "all",
    sections: [
      {
        id: "theme",
        title: "화면 테마",
        description: "라이트 / 다크 / 시스템 자동",
        render: () => <ThemeSwitcher />,
      },
      {
        id: "assets",
        title: "내 자산",
        description: "사용 중인 벤더·제품을 등록하면 영향받는 CVE 만 추려서 알려드립니다",
        render: () => <AssetsManager />,
      },
    ],
  },
  {
    id: "ingestion",
    title: "데이터 수집",
    icon: Key,
    audience: "admin",
    sections: [
      {
        id: "external-keys",
        title: "외부 데이터 소스 API 키",
        description: "운영자 전용 — 등록한 키로 모든 사용자의 수집이 동작합니다",
        render: () => (
          <div className="space-y-4">
            <ApiKeyField settingKey="nvdApiKey" />
            <ApiKeyField settingKey="githubToken" />
          </div>
        ),
      },
      {
        id: "mitre-backfill",
        title: "MITRE 전체 백필",
        description: "최초 1회 전체 백필 후 자동 델타 수집으로 전환",
        render: () => <MitreBackfillPanel />,
      },
    ],
  },
  {
    id: "ai",
    title: "AI 분석",
    icon: Sparkles,
    // PR 10-CP2 이후 user-scoped — 일반 사용자도 자기 Claude credential 등록 가능.
    audience: "all",
    sections: [
      {
        id: "ai-analysis",
        title: "Claude 연동",
        description: "AI 분석에 사용할 본인 Claude 계정과 모델 — 사용자별로 분리됩니다",
        render: () => <ClaudeIntegrationPanel />,
      },
    ],
  },
  {
    id: "system",
    title: "시스템",
    icon: Server,
    audience: "admin",
    sections: [
      {
        id: "resources",
        title: "내부 자원 점검",
        description: "DB / Redis / Meilisearch 상태와 사용량 확인",
        render: () => (
          <Link
            href="/settings/resources"
            className="group flex items-center justify-between gap-3 rounded-lg border border-neutral-200 bg-white p-4 transition-colors hover:border-sky-400 hover:bg-sky-50/40 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40 dark:hover:bg-surface-2"
          >
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300">
                <Database className="h-4 w-4" />
              </div>
              <div>
                <div className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
                  자원 점검 화면 열기
                </div>
                <p className="mt-0.5 text-xs text-neutral-600 dark:text-neutral-500">
                  DB · Redis · Meilisearch 사용량과 통계 갱신·캐시 비우기·인덱스 초기화
                </p>
              </div>
            </div>
            <ChevronRight className="h-4 w-4 text-neutral-500 transition-transform group-hover:translate-x-0.5 group-hover:text-neutral-700 dark:group-hover:text-neutral-200" />
          </Link>
        ),
      },
      {
        id: "version",
        title: "버전 정보",
        description: "현재 빌드와 DB 마이그레이션 상태",
        render: () => <VersionPanel />,
      },
      {
        id: "storage-notes",
        title: "설정 저장 위치",
        description: "각 설정이 어디에 저장되는지 안내",
        render: () => (
          <ul className="list-disc space-y-1 pl-5 text-xs text-neutral-600 dark:text-neutral-500">
            <li>화면 테마 · 외부 API 키 — 이 기기의 브라우저에만 저장</li>
            <li>AI 인증 · 등록 자산 — 서버에 저장 (모든 기기에서 공유)</li>
          </ul>
        ),
      },
    ],
  },
];

export function SettingsLayout() {
  const { user, loading: authLoading } = useAuth();

  // 비로그인은 설정 페이지 자체를 못 봄 — 외부 키나 자원 점검 등 운영
  // 정보가 노출되면 안 되므로 /login 으로 즉시 우회.
  useEffect(() => {
    if (authLoading) return;
    if (!user && typeof window !== "undefined") {
      window.location.href = `/login?next=${encodeURIComponent("/settings")}`;
    }
  }, [user, authLoading]);

  // 실제 렌더할 카테고리 — 일반 사용자에겐 admin 전용을 통째로 숨김.
  const visibleCategories = useMemo(
    () =>
      CATEGORIES.filter((c) => c.audience === "all" || user?.isAdmin === true),
    [user?.isAdmin],
  );
  const visibleSectionIds = useMemo(
    () => visibleCategories.flatMap((c) => c.sections.map((s) => s.id)),
    [visibleCategories],
  );

  const [active, setActive] = useState<string>("");
  const observer = useRef<IntersectionObserver | null>(null);

  // 가시 섹션이 바뀌면 active 가 첫 항목으로 보정 (admin → 비admin 전환 등).
  useEffect(() => {
    if (!visibleSectionIds.length) return;
    setActive((prev) => (visibleSectionIds.includes(prev) ? prev : visibleSectionIds[0]));
  }, [visibleSectionIds]);

  // Scroll-spy: highlight the section closest to the top of the viewport.
  // Uses a band near the top (rootMargin top = -64px for sticky header,
  // bottom = -60% so a section is "active" once its top crosses ~40%
  // viewport height) so the nav lights up *as* the user reaches the
  // section, not when they scroll past it.
  //
  // Bottom sections reach this band naturally because the right column
  // has `pb-[60vh]` spacer below the last section — that ensures even
  // the document footer has enough room to scroll the last section's
  // top into the 40% observation band.
  useEffect(() => {
    if (typeof window === "undefined" || visibleSectionIds.length === 0) return;
    observer.current?.disconnect();
    const visible = new Map<string, number>();
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            visible.set(e.target.id, e.intersectionRatio);
          } else {
            visible.delete(e.target.id);
          }
        });
        if (visible.size === 0) return;
        const orderIndex = (id: string) => visibleSectionIds.indexOf(id);
        const next = [...visible.keys()].sort(
          (a, b) => orderIndex(a) - orderIndex(b),
        )[0];
        if (next) setActive(next);
      },
      {
        rootMargin: "-64px 0px -60% 0px",
        threshold: [0, 0.1, 0.5, 1],
      },
    );
    visibleSectionIds.forEach((id) => {
      const el = document.getElementById(id);
      if (el) obs.observe(el);
    });
    observer.current = obs;
    return () => obs.disconnect();
  }, [visibleSectionIds]);

  // Initial hash-based jump on mount (if user landed via /settings#assets etc).
  useEffect(() => {
    if (typeof window === "undefined") return;
    const hash = window.location.hash.slice(1);
    if (hash && visibleSectionIds.includes(hash)) {
      setActive(hash);
      // Defer scroll until layout settles.
      window.setTimeout(() => {
        document
          .getElementById(hash)
          ?.scrollIntoView({ behavior: "instant" as ScrollBehavior, block: "start" });
      }, 50);
    }
  }, [visibleSectionIds]);

  const handleNavClick = (id: string) => {
    setActive(id);
    if (typeof window !== "undefined") {
      history.replaceState(null, "", `#${id}`);
    }
  };

  const sections = useMemo(
    () => visibleCategories.flatMap((c) => c.sections),
    [visibleCategories],
  );

  // auth 결정 전 / 비로그인 우회 중 — 빈 placeholder 만 렌더.
  if (authLoading || !user) {
    return (
      <div className="mx-auto flex min-h-[calc(100vh-3.5rem)] max-w-7xl items-center justify-center px-6 py-12">
        <div className="inline-flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-400">
          <Lock className="h-4 w-4" />
          로그인 후 이용할 수 있는 화면입니다.
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto min-h-[calc(100vh-3.5rem)] max-w-7xl px-6 py-12">
      <header className="mb-8 flex items-end justify-between gap-3">
        <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">설정</h1>
        {user.isAdmin && (
          <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2.5 py-1 text-xs font-medium text-amber-800 dark:bg-amber-500/15 dark:text-amber-200">
            관리자 모드
          </span>
        )}
      </header>

      <div className="grid gap-8 lg:grid-cols-[220px_1fr]">
        {/* ── 좌측 목차 (모바일에서는 가로 카드 묶음으로 떨어짐) ─── */}
        <nav
          aria-label="설정 카테고리"
          className="lg:sticky lg:top-20 lg:self-start"
        >
          <ul className="space-y-5">
            {visibleCategories.map((cat) => {
              const Icon = cat.icon;
              const hasActive = cat.sections.some((s) => s.id === active);
              return (
                <li key={cat.id}>
                  <div
                    className={cn(
                      "mb-1.5 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider",
                      hasActive ? "text-neutral-200" : "text-neutral-500",
                    )}
                  >
                    <Icon className="h-3 w-3" />
                    {cat.title}
                  </div>
                  <ul className="space-y-0.5">
                    {cat.sections.map((s) => {
                      const isActive = s.id === active;
                      return (
                        <li key={s.id}>
                          <a
                            href={`#${s.id}`}
                            onClick={() => handleNavClick(s.id)}
                            className={cn(
                              "block rounded-full px-3 py-1.5 text-xs transition-all duration-150 active:scale-95",
                              isActive
                                ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                                : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100",
                            )}
                          >
                            {s.title}
                          </a>
                        </li>
                      );
                    })}
                  </ul>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* ── 우측 본문 ───────────────────────────────────────────── */}
        {/* min-w-0: a grid item's implicit min-width is its content's
            intrinsic size, so an un-truncated long string (e.g. the
            OAuth URL chip in ClaudeAuthPanel) can stretch this column
            past the template and break the page ratio.
            pb-[60vh]: leaves enough scroll room below the last section
            so the IntersectionObserver band (top 40% of viewport) can
            still highlight it. Without this the last 2–3 sections never
            "reach the top" and the nav stayed stuck on the previous
            entry. */}
        <div className="min-w-0 pb-[60vh]">
          {sections.map((s, i) => (
            <Section
              key={s.id}
              id={s.id}
              title={s.title}
              description={s.description}
              isFirst={i === 0}
            >
              {s.render()}
            </Section>
          ))}
        </div>
      </div>
    </div>
  );
}

function Section({
  id,
  title,
  description,
  isFirst,
  children,
}: {
  id: string;
  title: string;
  description: string;
  isFirst: boolean;
  children: React.ReactNode;
}) {
  return (
    <section
      id={id}
      // scroll-margin-top so anchor jumps clear the sticky page header.
      className={cn(
        "scroll-mt-20",
        isFirst ? "" : "mt-10 border-t border-neutral-200 pt-8 dark:border-neutral-800",
      )}
    >
      <h2 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">{title}</h2>
      {description ? (
        <p className="mt-1 mb-4 text-xs text-neutral-600 dark:text-neutral-500">{description}</p>
      ) : (
        <div className="mb-3" />
      )}
      {children}
    </section>
  );
}
