import type { Metadata } from "next";
import "./globals.css";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { Providers } from "@/components/providers";
import { FloatingDock } from "@/components/system/FloatingDock";

const SITE_URL = "https://www.kestrel.forum";
const SITE_TITLE = "Kestrel — 실시간 CVE & 제로데이 모니터링";
const SITE_DESC =
  "Kestrel은 NVD, Exploit-DB, GitHub Advisory, MITRE를 실시간으로 집약한 사이버 보안 전문가용 취약점 대시보드입니다.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: SITE_TITLE,
  description: SITE_DESC,
  keywords: ["Kestrel", "CVE", "zero-day", "vulnerability", "security", "NVD", "exploit"],
  // 링크 공유 미리보기(카카오톡·슬랙·디스코드·페북). og:image 는 app/opengraph-image.tsx
  // 파일 컨벤션이 자동 연결한다. (PR 10-FF)
  openGraph: {
    type: "website",
    url: SITE_URL,
    siteName: "Kestrel",
    title: SITE_TITLE,
    description: SITE_DESC,
    locale: "ko_KR",
  },
  // 트위터는 전용 카드 + og:image 폴백 사용.
  twitter: {
    card: "summary_large_image",
    title: SITE_TITLE,
    description: SITE_DESC,
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
