import { VisitorBadge } from "./VisitorBadge";

const _CONTACT_EMAIL = "y202437030@ync.ac.kr";

export function Footer() {
  const year = new Date().getFullYear();
  return (
    <footer className="mt-16 border-t border-neutral-200 bg-white dark:border-neutral-800 dark:bg-surface-0">
      <div className="mx-auto flex max-w-7xl flex-col gap-2 px-6 py-6 text-xs text-neutral-600 dark:text-neutral-500">
        {/* 상단 줄: 데이터 출처 · 방문자 chip */}
        <div className="flex flex-col items-center justify-between gap-2 sm:flex-row">
          <span>Kestrel · 데이터 출처: NVD · Exploit-DB · GitHub Advisory · MITRE</span>
          <VisitorBadge />
        </div>
        {/* 하단 줄: 저작권 · 운영 문의 · 사용 안내 */}
        <div className="flex flex-col items-center justify-between gap-1 sm:flex-row">
          <span>
            © {year} Kestrel ·{" "}
            <a
              href={`mailto:${_CONTACT_EMAIL}`}
              className="text-neutral-700 hover:underline dark:text-neutral-300"
            >
              {_CONTACT_EMAIL}
            </a>
          </span>
          <span>교육 및 방어 목적 정보 제공.</span>
        </div>
        {/* 법적 페이지 */}
        <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 pt-1 sm:justify-end">
          <a href="/privacy" className="text-neutral-600 hover:underline dark:text-neutral-400">
            개인정보처리방침
          </a>
          <span className="text-neutral-300 dark:text-neutral-700">·</span>
          <a href="/terms" className="text-neutral-600 hover:underline dark:text-neutral-400">
            이용약관
          </a>
        </div>
      </div>
    </footer>
  );
}
