import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "취약점 조회 — Kestrel",
  description: "CVE 취약점 검색 · CVSS(이론)·EPSS(예측)·KEV(실측) 기반 패치 우선순위 · AI 심층 분석.",
  openGraph: {
    title: "취약점 조회 — Kestrel",
    description: "CVE 검색 · CVSS·EPSS·KEV 우선순위 · AI 분석.",
  },
};

export default function CvesLayout({ children }: { children: React.ReactNode }) {
  return children;
}
