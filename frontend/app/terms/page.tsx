import type { Metadata } from "next";
import Link from "next/link";
import { ChevronLeft, FileText } from "lucide-react";

export const metadata: Metadata = {
  title: "이용약관 — Kestrel",
  description: "Kestrel 서비스 이용약관.",
};

const CONTACT = "y202437030@ync.ac.kr";
const UPDATED = "2026-06-10";

function Section({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-neutral-200 py-5 first:border-0 dark:border-neutral-800">
      <h2 className="flex items-baseline gap-2 text-base font-semibold text-neutral-100">
        <span className="text-sm font-bold text-sky-500">{n}</span>
        {title}
      </h2>
      <div className="mt-2 space-y-2 text-sm leading-relaxed text-neutral-400">{children}</div>
    </section>
  );
}

export default function TermsPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <Link
        href="/"
        className="inline-flex items-center gap-1 text-sm text-neutral-500 hover:text-neutral-300"
      >
        <ChevronLeft className="h-4 w-4" />
        홈으로
      </Link>

      <header className="mt-5 flex items-center gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-sky-500/15 ring-1 ring-sky-500/30">
          <FileText className="h-5 w-5 text-sky-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-neutral-100">이용약관</h1>
          <p className="text-xs text-neutral-500">최종 개정일: {UPDATED}</p>
        </div>
      </header>

      <p className="mt-5 text-sm leading-relaxed text-neutral-400">
        본 약관은 Kestrel 서비스 이용에 관한 조건을 정합니다. 서비스를 이용함으로써 본 약관에 동의한
        것으로 간주됩니다.
      </p>

      <div className="mt-6 rounded-2xl border border-neutral-200 px-6 py-2 dark:border-neutral-800 bg-surface-1 shadow-sm">
        <Section n={1} title="서비스 개요">
          <p>
            Kestrel은 CVE 취약점 정보(NVD·Exploit-DB·GitHub Advisory·MITRE)를 집계·검색하고 AI 기반
            분석을 제공하는 취약점 인텔리전스 서비스입니다. 본 서비스는{" "}
            <strong className="text-neutral-200">교육 및 방어(보안) 목적</strong>의 정보 제공을 위한
            것입니다.
          </p>
        </Section>
        <Section n={2} title="AI 분석 결과의 한계">
          <p>
            AI가 생성한 공격 기법·페이로드·완화책은 <strong className="text-neutral-200">참고용</strong>
            이며 정확성·완전성을 보장하지 않습니다. 실제 대응 전에는 반드시 전문가 검토를 거쳐야 하며,
            결과 이용에 따른 책임은 이용자에게 있습니다.
          </p>
        </Section>
        <Section n={3} title="금지 행위">
          <p>제공되는 정보를 다음 목적으로 사용해서는 안 됩니다.</p>
          <ul className="list-disc space-y-1 pl-5">
            <li>권한 없는 시스템에 대한 무단 침투·공격 등 불법 행위</li>
            <li>타인의 권리 침해, 악성코드 유포, 서비스 방해</li>
            <li>관련 법령 또는 본 약관을 위반하는 일체의 행위</li>
          </ul>
          <p>이용자는 본인이 권한을 가진 자산에 대해서만, 합법적 범위에서 정보를 활용해야 합니다.</p>
        </Section>
        <Section n={4} title="계정">
          <p>
            이용자는 계정 정보를 안전하게 관리할 책임이 있으며, 계정을 통한 활동에 대한 책임은
            이용자에게 있습니다. 약관 위반 시 서비스 이용이 제한될 수 있습니다.
          </p>
        </Section>
        <Section n={5} title="면책">
          <p>
            본 서비스는 정보를 "있는 그대로" 제공하며, 데이터의 정확성·가용성·특정 목적 적합성을
            보증하지 않습니다. 서비스 이용 또는 이용 불가로 인한 손해에 대해 책임지지 않습니다.
          </p>
        </Section>
        <Section n={6} title="문의">
          <p>
            문의:{" "}
            <a href={`mailto:${CONTACT}`} className="text-sky-400 hover:underline">
              {CONTACT}
            </a>
          </p>
        </Section>
      </div>
    </div>
  );
}
