import Link from "next/link";
import { Bird, Settings } from "lucide-react";

export function Header() {
  return (
    <header className="sticky top-0 z-40 border-b border-neutral-800 bg-surface-0/80 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold text-neutral-100">
          <Bird className="h-5 w-5 text-blue-500" />
          <span className="tracking-tight">Kestrel</span>
        </Link>
        <nav className="flex items-center gap-5 text-sm text-neutral-400">
          <Link href="/" className="hover:text-neutral-100">
            대시보드
          </Link>
          <a
            href="https://nvd.nist.gov/"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-neutral-100"
          >
            NVD
          </a>
          <span className="hidden text-xs text-neutral-600 sm:inline">커뮤니티 준비 중</span>
          <Link
            href="/settings"
            className="flex items-center gap-1 rounded-md border border-neutral-800 px-2 py-1 hover:border-neutral-700 hover:text-neutral-100"
            aria-label="설정"
          >
            <Settings className="h-4 w-4" />
            <span className="hidden sm:inline">설정</span>
          </Link>
        </nav>
      </div>
    </header>
  );
}
