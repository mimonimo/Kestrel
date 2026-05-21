"use client";

import Link from "next/link";
import {
  ChevronRight,
  Database,
  FlaskConical,
  Key,
  Server,
  Sparkles,
  User,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { ApiKeyField } from "@/components/settings/ApiKeyField";
import { AssetsManager } from "@/components/settings/AssetsManager";
import { ClaudeIntegrationPanel } from "@/components/settings/ClaudeIntegrationPanel";
import { LabKindStatsPanel } from "@/components/settings/LabKindStatsPanel";
import { MitreBackfillPanel } from "@/components/settings/MitreBackfillPanel";
import { SandboxSessionsPanel } from "@/components/settings/SandboxSessionsPanel";
import { SynthesizerCachePanel } from "@/components/settings/SynthesizerCachePanel";
import { ThemeSwitcher } from "@/components/settings/ThemeSwitcher";
import { VersionPanel } from "@/components/settings/VersionPanel";
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
  sections: SectionDef[];
}

// Single source of truth — sidebar nav and the body sections both
// read from this list. Add a section here and it shows up in both.
const CATEGORIES: CategoryDef[] = [
  {
    id: "personal",
    title: "개인 설정",
    icon: User,
    sections: [
      {
        id: "theme",
        title: "화면 테마",
        description: "다크 / 라이트 / 시스템 설정 자동 감지 중에서 선택합니다.",
        render: () => <ThemeSwitcher />,
      },
      {
        id: "assets",
        title: "내 자산",
        description: "운영 중인 벤더·제품을 등록하면 영향 받는 CVE 만 따로 보입니다.",
        render: () => <AssetsManager />,
      },
    ],
  },
  {
    id: "ingestion",
    title: "데이터 수집",
    icon: Key,
    sections: [
      {
        id: "external-keys",
        title: "외부 데이터 소스 API 키",
        description: "비워도 동작하지만, 등록하면 수집 속도가 빨라집니다.",
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
        description: "최초 1회만 실행. 평소엔 자동 델타 동기화.",
        render: () => <MitreBackfillPanel />,
      },
    ],
  },
  {
    id: "ai",
    title: "AI 분석",
    icon: Sparkles,
    sections: [
      {
        id: "ai-analysis",
        title: "Claude 연동",
        description: "AI 심층 분석과 실습 환경 합성에 사용되는 Claude 인증과 모델을 한 곳에서.",
        render: () => <ClaudeIntegrationPanel />,
      },
    ],
  },
  {
    id: "sandbox",
    title: "샌드박스",
    icon: FlaskConical,
    sections: [
      {
        id: "sandbox-sessions",
        title: "실행 중인 샌드박스 세션",
        description: "실습 컨테이너 목록 + vulhub 동기화.",
        render: () => <SandboxSessionsPanel />,
      },
      {
        id: "synth-cache",
        title: "합성된 실습 환경 저장 공간",
        description: "AI 합성 이미지의 디스크 사용량입니다.",
        render: () => <SynthesizerCachePanel />,
      },
      {
        id: "lab-stats",
        title: "실습 환경 출처별 분포",
        description: "vulhub · 표준 · 합성 비율과 유형별 점유율.",
        render: () => <LabKindStatsPanel />,
      },
    ],
  },
  {
    id: "system",
    title: "시스템",
    icon: Server,
    sections: [
      {
        id: "resources",
        title: "내부 자원 관리",
        description: "DB · Redis · 검색 인덱스 사용량 + 점검 동작.",
        render: () => (
          <Link
            href="/settings/resources"
            className="group flex items-center justify-between gap-3 rounded-lg border border-neutral-800 bg-surface-1 p-4 transition-colors hover:border-sky-500/40 hover:bg-surface-2"
          >
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500/15 text-sky-700 dark:text-sky-300 ring-1 ring-sky-500/30">
                <Database className="h-4 w-4" />
              </div>
              <div>
                <div className="text-sm font-medium text-neutral-100">
                  내부 자원 관리 화면 열기
                </div>
                <p className="mt-0.5 text-xs text-neutral-500">
                  DB / Redis / Meilisearch 사용량 + 통계 갱신·캐시 비우기·인덱스 초기화
                </p>
              </div>
            </div>
            <ChevronRight className="h-4 w-4 text-neutral-500 transition-transform group-hover:translate-x-0.5 group-hover:text-neutral-200" />
          </Link>
        ),
      },
      {
        id: "version",
        title: "버전 정보 / 업데이트",
        description: "현재 빌드와 DB 마이그레이션 상태.",
        render: () => <VersionPanel />,
      },
      {
        id: "storage-notes",
        title: "설정 저장 위치 안내",
        description: "",
        render: () => (
          <ul className="list-disc space-y-1 pl-5 text-xs text-neutral-500">
            <li>
              화면 테마와 외부 데이터 소스 키는 이 기기의 브라우저 안에만
              저장됩니다.
            </li>
            <li>다른 기기·브라우저에서는 다시 입력해 주세요.</li>
            <li>
              AI 분석 키와 등록한 자산은 서버에 안전하게 저장되어 모든
              기기에서 공유됩니다.
            </li>
          </ul>
        ),
      },
    ],
  },
];

const ALL_SECTION_IDS = CATEGORIES.flatMap((c) => c.sections.map((s) => s.id));

export function SettingsLayout() {
  const [active, setActive] = useState<string>(ALL_SECTION_IDS[0]);
  const observer = useRef<IntersectionObserver | null>(null);

  // Scroll-spy: highlight the section closest to the top of the viewport.
  // Uses a band near the top (rootMargin top = -64px for sticky header,
  // bottom = -60% so a section is "active" once its top crosses ~40%
  // viewport height) so the nav lights up *as* the user reaches the
  // section, not when they scroll past it.
  useEffect(() => {
    if (typeof window === "undefined") return;
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
        // Pick the visible section earliest in document order — matches
        // the user's intuition of "what's at the top of my screen".
        const orderIndex = (id: string) => ALL_SECTION_IDS.indexOf(id);
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
    ALL_SECTION_IDS.forEach((id) => {
      const el = document.getElementById(id);
      if (el) obs.observe(el);
    });
    observer.current = obs;
    return () => obs.disconnect();
  }, []);

  // Initial hash-based jump on mount (if user landed via /settings#assets etc).
  useEffect(() => {
    if (typeof window === "undefined") return;
    const hash = window.location.hash.slice(1);
    if (hash && ALL_SECTION_IDS.includes(hash)) {
      setActive(hash);
      // Defer scroll until layout settles.
      window.setTimeout(() => {
        document
          .getElementById(hash)
          ?.scrollIntoView({ behavior: "instant" as ScrollBehavior, block: "start" });
      }, 50);
    }
  }, []);

  const handleNavClick = (id: string) => {
    setActive(id);
    if (typeof window !== "undefined") {
      history.replaceState(null, "", `#${id}`);
    }
  };

  const sections = useMemo(
    () => CATEGORIES.flatMap((c) => c.sections),
    [],
  );

  return (
    <div className="mx-auto max-w-6xl px-6 py-12">
      <header className="mb-8">
        <h1 className="text-2xl font-bold text-neutral-100">설정</h1>
      </header>

      <div className="grid gap-8 lg:grid-cols-[220px_1fr]">
        {/* ── 좌측 목차 (모바일에서는 가로 카드 묶음으로 떨어짐) ─── */}
        <nav
          aria-label="설정 카테고리"
          className="lg:sticky lg:top-20 lg:self-start"
        >
          <ul className="space-y-5">
            {CATEGORIES.map((cat) => {
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
                              "block rounded-md border-l-2 px-3 py-1.5 text-xs transition-colors",
                              isActive
                                ? "border-sky-400 bg-sky-500/10 text-sky-800 dark:text-sky-200"
                                : "border-transparent text-neutral-400 hover:border-sky-500/30 hover:bg-sky-500/5 hover:text-sky-800 dark:hover:text-sky-200",
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
            past the template and break the page ratio. */}
        <div className="min-w-0">
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
        isFirst ? "" : "mt-10 border-t border-neutral-800 pt-8",
      )}
    >
      <h2 className="text-base font-semibold text-neutral-100">{title}</h2>
      {description ? (
        <p className="mt-1 mb-4 text-xs text-neutral-500">{description}</p>
      ) : (
        <div className="mb-3" />
      )}
      {children}
    </section>
  );
}
