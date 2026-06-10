import type { Metadata } from "next";
import Link from "next/link";
import { ChevronLeft, ShieldCheck } from "lucide-react";

export const metadata: Metadata = {
  title: "개인정보처리방침 — Kestrel",
  description: "Kestrel이 수집·이용하는 개인정보 항목과 처리 방침 안내.",
};

const CONTACT = "y202437030@ync.ac.kr";
const UPDATED = "2026-06-10";

function Section({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-neutral-200 py-5 first:border-0 first:pt-0 dark:border-neutral-800">
      <h2 className="flex items-baseline gap-2 text-base font-semibold text-neutral-100">
        <span className="text-sm font-bold text-sky-500">{n}</span>
        {title}
      </h2>
      <div className="mt-2 space-y-2 text-sm leading-relaxed text-neutral-400">{children}</div>
    </section>
  );
}

export default function PrivacyPage() {
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
          <ShieldCheck className="h-5 w-5 text-sky-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-neutral-100">개인정보처리방침</h1>
          <p className="text-xs text-neutral-500">최종 개정일: {UPDATED}</p>
        </div>
      </header>

      <p className="mt-5 text-sm leading-relaxed text-neutral-400">
        Kestrel은 이용자의 개인정보를 중요하게 생각하며, 서비스 제공에 필요한 최소한의 정보만
        수집합니다. 본 방침은 수집 항목·이용 목적·보관·이용자 권리를 안내합니다.
      </p>

      <div className="mt-6 rounded-2xl border border-neutral-200 bg-white px-6 dark:border-neutral-800 dark:bg-surface-1">
        <Section n={1} title="수집하는 개인정보 항목">
          <ul className="list-disc space-y-1 pl-5">
            <li>회원가입·로그인: 이메일 주소, 비밀번호(단방향 해시 저장), 닉네임</li>
            <li>서비스 이용 기록: 접속 로그(IP, User-Agent, 요청 경로/시각), 작성한 글·댓글·AI 분석 기록</li>
            <li>인증 쿠키: 로그인 세션 유지를 위한 HttpOnly 쿠키</li>
          </ul>
          <p>마케팅·광고 목적의 정보는 수집하지 않습니다.</p>
        </Section>
        <Section n={2} title="개인정보의 이용 목적">
          <ul className="list-disc space-y-1 pl-5">
            <li>회원 식별 및 로그인, 이메일 인증, 비밀번호 재설정</li>
            <li>서비스 제공(취약점 조회·AI 분석·커뮤니티) 및 부정 이용 방지</li>
            <li>서비스 안정성·보안 모니터링(접속 로그)</li>
          </ul>
        </Section>
        <Section n={3} title="이메일 발송">
          <p>
            이메일은 <strong className="text-neutral-200">트랜잭션 목적</strong>(가입 이메일 인증,
            비밀번호 재설정)으로만, 사용자의 명시적 요청 시에만 발송합니다. 마케팅·뉴스레터는 발송하지
            않으며, 발송에는 Amazon SES(AWS)를 이용합니다.
          </p>
        </Section>
        <Section n={4} title="보유 및 이용 기간">
          <ul className="list-disc space-y-1 pl-5">
            <li>회원 정보: 회원 탈퇴 시 지체 없이 파기</li>
            <li>접속 로그: 보안 목적상 일정 기간 보관 후 자동 삭제</li>
            <li>관련 법령에 따라 보존이 필요한 경우 해당 기간 동안 보관</li>
          </ul>
        </Section>
        <Section n={5} title="제3자 제공 및 처리위탁">
          <p>
            이용자의 개인정보를 제3자에게 판매·제공하지 않습니다. 다만 서비스 운영에 필요한 범위에서
            인프라(AWS)·이메일 발송(Amazon SES) 등 클라우드 서비스를 이용합니다.
          </p>
        </Section>
        <Section n={6} title="이용자의 권리">
          <p>
            이용자는 언제든지 본인의 개인정보 열람·정정·삭제 및 회원 탈퇴를 요청할 수 있습니다. 설정
            페이지에서 직접 처리하거나 아래 연락처로 요청해 주세요.
          </p>
        </Section>
        <Section n={7} title="쿠키">
          <p>로그인 세션 유지를 위해 HttpOnly 인증 쿠키를 사용합니다. 광고·추적용 쿠키는 사용하지 않습니다.</p>
        </Section>
        <Section n={8} title="문의">
          <p>
            개인정보 관련 문의:{" "}
            <a href={`mailto:${CONTACT}`} className="text-sky-400 hover:underline">
              {CONTACT}
            </a>
          </p>
        </Section>
      </div>
    </div>
  );
}
