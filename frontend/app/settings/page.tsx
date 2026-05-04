import type { Metadata } from "next";
import { AiSettingsForm } from "@/components/settings/AiSettingsForm";
import { ApiKeyField } from "@/components/settings/ApiKeyField";
import { AssetsManager } from "@/components/settings/AssetsManager";
import { LabKindStatsPanel } from "@/components/settings/LabKindStatsPanel";
import { SynthesizerCachePanel } from "@/components/settings/SynthesizerCachePanel";
import { ThemeSwitcher } from "@/components/settings/ThemeSwitcher";

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
          테마와 외부 API 키를 이 기기에서만 관리합니다. 모든 값은 브라우저
          localStorage에 저장되며 서버로 전송되지 않습니다.
        </p>
      </header>

      <Section title="테마" description="다크 / 라이트 / 시스템 자동 감지 중에서 선택합니다.">
        <ThemeSwitcher />
      </Section>

      <Section
        title="API 키"
        description="셀프 호스팅 시 외부 API의 레이트 리밋과 인증에 사용됩니다. 비워 두면 기본 키리스 모드로 동작합니다."
      >
        <div className="space-y-4">
          <ApiKeyField settingKey="nvdApiKey" />
          <ApiKeyField settingKey="githubToken" />
        </div>
      </Section>

      <Section
        title="AI 분석 설정"
        description="CVE 상세 페이지의 'AI 심층 분석'에 사용할 LLM 제공자·모델·API 키를 설정합니다. 키는 서버 DB에 저장되며 응답에서는 가려집니다."
      >
        <AiSettingsForm />
      </Section>

      <Section
        title="내 자산"
        description="등록한 벤더·제품은 파싱된 CVE의 CPE 정보와 매칭되어 대시보드 상단 '내 시스템 취약점'에 노출됩니다."
      >
        <AssetsManager />
      </Section>

      <Section
        title="합성된 lab 캐시"
        description="AI 합성으로 만든 docker 이미지의 캐시 상태입니다. 합성 호출 시 자동 LRU 회수가 돌지만, 지금 강제 정리도 가능합니다."
      >
        <SynthesizerCachePanel />
      </Section>

      <Section
        title="CVE → lab 매핑 분포"
        description="vulhub / generic / synthesized 각 provenance 와 lab kind 별 점유율. 한 클래스로 쏠려있다면 합성 prompt 또는 classifier 룰 편향 신호."
      >
        <LabKindStatsPanel />
      </Section>

      <Section title="저장 위치" description="" muted>
        <ul className="list-disc space-y-1 pl-5 text-xs text-neutral-500">
          <li>키와 테마 설정은 모두 브라우저 localStorage에 저장됩니다.</li>
          <li>다른 기기·브라우저로 옮길 때는 다시 입력해야 합니다.</li>
          <li>
            서비스 정식 배포 단계에서는 백엔드 환경변수
            <code className="mx-1 rounded bg-surface-2 px-1 py-0.5 font-mono text-[11px]">
              NVD_API_KEY
            </code>
            ·
            <code className="mx-1 rounded bg-surface-2 px-1 py-0.5 font-mono text-[11px]">
              GITHUB_TOKEN
            </code>
            으로 옮길 예정입니다.
          </li>
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
