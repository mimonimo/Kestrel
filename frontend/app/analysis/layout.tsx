import type { Metadata } from "next";

// 개인 분석 기록 영역 — 색인 제외.
export const metadata: Metadata = {
  title: "내 분석 — Kestrel",
  description: "내가 실행한 CVE AI 심층 분석 기록.",
  robots: { index: false, follow: false },
};

export default function AnalysisLayout({ children }: { children: React.ReactNode }) {
  return children;
}
