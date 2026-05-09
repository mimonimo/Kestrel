import type { Metadata } from "next";
import Link from "next/link";
import { ChevronRight, Server } from "lucide-react";
import { AiSettingsForm } from "@/components/settings/AiSettingsForm";
import { ApiKeyField } from "@/components/settings/ApiKeyField";
import { AssetsManager } from "@/components/settings/AssetsManager";
import { ClaudeAuthPanel } from "@/components/settings/ClaudeAuthPanel";
import { LabKindStatsPanel } from "@/components/settings/LabKindStatsPanel";
import { SandboxSessionsPanel } from "@/components/settings/SandboxSessionsPanel";
import { SynthesizerCachePanel } from "@/components/settings/SynthesizerCachePanel";
import { ThemeSwitcher } from "@/components/settings/ThemeSwitcher";
import { VersionPanel } from "@/components/settings/VersionPanel";

export const metadata: Metadata = {
  title: "설정 — Kestrel",
  description: "테마와 API 키를 관리합니다.",
};

export default function SettingsPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-12">
      <header className="mb-8">
        <h1 className="text-2xl font-bold text-neutral-100">설정</h1>
        <p className="mt-1 text-sm text-neutral-500">
          테마와 외부 API 키, 자산 정보 등을 관리합니다. 화면 설정과 외부 API
          키는 이 기기 안에만 저장되며 외부로 전송되지 않습니다.
        </p>
      </header>

      <Section title="화면 테마" description="다크 / 라이트 / 시스템 설정 자동 감지 중에서 선택합니다.">
        <ThemeSwitcher />
      </Section>

      <Section
        title="외부 데이터 소스 API 키"
        description="NVD · GitHub Advisory 데이터를 더 빠르게 받아오기 위한 키입니다. 비워 두어도 동작하지만, 등록하면 수집 속도와 안정성이 좋아집니다."
      >
        <div className="space-y-4">
          <ApiKeyField settingKey="nvdApiKey" />
          <ApiKeyField settingKey="githubToken" />
        </div>
      </Section>

      <Section
        title="Claude 로그인"
        description="대시보드에서 직접 Claude 구독으로 로그인합니다. 호스트의 CLI 인증을 마운트할 필요 없이, 로그인 한 번으로 백엔드의 영구 저장 공간에 자격증명이 저장되어 컨테이너를 재시작해도 유지됩니다."
      >
        <ClaudeAuthPanel />
      </Section>

      <Section
        title="AI 분석 모델 선택"
        description="위에서 로그인한 Claude 구독을 어떤 모델로 호출할지 선택합니다. 한 번에 하나의 라벨만 활성화됩니다."
      >
        <AiSettingsForm />
      </Section>

      <Section
        title="내 자산"
        description="운영 중인 벤더·제품을 등록하면 그에 영향을 주는 CVE 만 모아 대시보드 상단 '내 시스템 취약점' 카드에 표시됩니다."
      >
        <AssetsManager />
      </Section>

      <Section
        title="실행 중인 샌드박스 세션"
        description="현재 띄워진 실습 환경 컨테이너 목록입니다. 만료 전이라도 즉시 정지할 수 있고, vulhub 공식 환경을 새로 받아오는 동기화도 여기서 실행합니다."
      >
        <SandboxSessionsPanel />
      </Section>

      <Section
        title="합성된 실습 환경 저장 공간"
        description="AI 합성으로 만든 실습 환경 이미지의 사용량입니다. 합성이 호출될 때마다 자동으로 오래된 이미지가 정리되며, 필요할 때 즉시 정리도 가능합니다."
      >
        <SynthesizerCachePanel />
      </Section>

      <Section
        title="실습 환경 출처별 분포"
        description="vulhub 공식 재현 / 표준 환경 / AI 합성 비율과 취약점 유형별 점유율을 보여줍니다. 한쪽으로 쏠려 있다면 합성 품질을 점검할 신호일 수 있습니다."
      >
        <LabKindStatsPanel />
      </Section>

      <Section
        title="내부 자원 관리"
        description="데이터베이스 / Redis / 검색 인덱스의 사용량을 확인하고 점검 동작을 실행하는 별도 화면입니다."
      >
        <Link
          href="/settings/resources"
          className="group flex items-center justify-between gap-3 rounded-lg border border-neutral-800 bg-surface-1 p-4 transition-colors hover:border-sky-500/40 hover:bg-surface-2"
        >
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30">
              <Server className="h-4 w-4" />
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
      </Section>

      <Section
        title="버전 정보 / 업데이트"
        description="현재 실행 중인 빌드와 DB 마이그레이션 상태입니다. 새 버전이 나오면 아래 명령 한 줄로 안전하게 업데이트할 수 있습니다."
      >
        <VersionPanel />
      </Section>

      <Section title="설정 저장 위치 안내" description="" muted>
        <ul className="list-disc space-y-1 pl-5 text-xs text-neutral-500">
          <li>화면 테마와 외부 데이터 소스 키는 이 기기의 브라우저 안에만 저장됩니다.</li>
          <li>다른 기기·브라우저에서는 다시 입력해 주세요.</li>
          <li>AI 분석 키와 등록한 자산은 서버에 안전하게 저장되어 모든 기기에서 공유됩니다.</li>
        </ul>
      </Section>
    </div>
  );
}

function Section({
  title,
  description,
  children,
  muted = false,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
  muted?: boolean;
}) {
  return (
    <section className="mb-10 border-t border-neutral-800 pt-8 first:border-t-0 first:pt-0">
      <h2 className={muted ? "text-sm font-semibold text-neutral-400" : "text-base font-semibold text-neutral-100"}>
        {title}
      </h2>
      {description && <p className="mt-1 mb-4 text-xs text-neutral-500">{description}</p>}
      {!description && <div className="mb-3" />}
      {children}
    </section>
  );
}
