export function Footer() {
  return (
    <footer className="mt-16 border-t border-neutral-800 bg-surface-0">
      <div className="mx-auto max-w-7xl px-6 py-6 text-xs text-neutral-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <span>CVE Watch · 데이터 출처: NVD, Exploit-DB, GitHub Advisory</span>
        <span>본 서비스는 교육 및 방어 목적 정보 제공을 위한 것입니다.</span>
      </div>
    </footer>
  );
}
