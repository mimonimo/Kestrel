import type { Metadata } from "next";
import "./globals.css";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { Providers } from "@/components/providers";
import { StatusBanner } from "@/components/system/StatusBanner";

export const metadata: Metadata = {
  title: "Kestrel — 실시간 CVE & 제로데이 모니터링",
  description:
    "Kestrel은 NVD, Exploit-DB, GitHub Advisory를 실시간으로 집약한 사이버 보안 전문가용 취약점 대시보드입니다.",
  keywords: ["Kestrel", "CVE", "zero-day", "vulnerability", "security", "NVD", "exploit"],
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
          <StatusBanner />
          <main className="flex-1">{children}</main>
          <Footer />
        </Providers>
      </body>
    </html>
  );
}
