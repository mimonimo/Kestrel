import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "커뮤니티 — Kestrel",
  description: "보안 분석가들이 공유한 취약점 AI 심층 분석과 토론을 둘러보세요.",
  openGraph: {
    title: "커뮤니티 — Kestrel",
    description: "보안 분석가들이 공유한 취약점 AI 심층 분석과 토론.",
  },
};

export default function CommunityLayout({ children }: { children: React.ReactNode }) {
  return children;
}
