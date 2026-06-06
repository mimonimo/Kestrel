import type { Metadata } from "next";
import "./globals.css";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { Providers } from "@/components/providers";
import { FloatingDock } from "@/components/system/FloatingDock";

const SITE_URL = "https://www.kestrel.forum";
const SITE_TITLE = "Kestrel — 실시간 CVE & 제로데이 모니터링";
const SITE_DESC = "실시간 CVE·제로데이 모니터링과 분석 커뮤니티, Kestrel";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: SITE_TITLE,
  description: SITE_DESC,
  keywords: ["Kestrel", "CVE", "zero-day", "vulnerability", "security", "NVD", "exploit"],
  // 링크 공유 미리보기(카카오톡·슬랙·디스코드·페북). og:image 는 정적 PNG(public/og.png)
  // — 동적 ImageResponse 는 self-host standalone 에서 satori CSS 한계 + WASM 트레이싱
  // 누락으로 502 가 나서, 빌드 타임에 미리 렌더한 정적 이미지를 쓴다. (PR 10-FI2)
  openGraph: {
    type: "website",
    url: SITE_URL,
    siteName: "Kestrel",
    title: SITE_TITLE,
    description: SITE_DESC,
    locale: "ko_KR",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "Kestrel" }],
  },
  twitter: {
    card: "summary_large_image",
    title: SITE_TITLE,
    description: SITE_DESC,
    images: ["/og.png"],
  },
};

// Inline pre-hydration script: applies the saved theme class before React
// mounts to eliminate the flash of wrong theme on first paint.
const themeBoot = `
(function() {
  try {
    var stored = localStorage.getItem('kestrel:theme');
    var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    var resolved = stored === 'light' ? 'light' : (stored === 'dark' ? 'dark' : (prefersDark ? 'dark' : 'light'));
    var root = document.documentElement;
    root.classList.toggle('dark', resolved === 'dark');
    root.classList.toggle('light', resolved === 'light');
    root.style.colorScheme = resolved;
  } catch (_) {
    document.documentElement.classList.add('dark');
  }
})();
`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBoot }} />
      </head>
      <body className="min-h-screen flex flex-col">
        <Providers>
          <Header />
          <main className="flex-1">{children}</main>
          <FloatingDock />
          <Footer />
        </Providers>
      </body>
    </html>
  );
}
