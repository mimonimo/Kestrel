export function Footer() {
  return (
    <footer className="mt-16 border-t border-neutral-200 bg-white dark:border-neutral-800 dark:bg-surface-0">
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-2 px-6 py-6 text-xs text-neutral-600 dark:text-neutral-500 sm:flex-row">
        <span>Kestrel · 데이터 출처: NVD · Exploit-DB · GitHub Advisory · MITRE</span>
        <span>교육 및 방어 목적 정보 제공.</span>
      </div>
    </footer>
  );
}
