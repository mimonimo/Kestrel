import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <h1 className="text-5xl font-bold text-neutral-100 mb-3">404</h1>
      <p className="text-neutral-400 mb-6">해당 CVE를 찾을 수 없습니다.</p>
      <Link
        href="/"
        className="text-sm text-blue-400 hover:text-blue-300 hover:underline"
      >
        대시보드로 돌아가기
      </Link>
    </div>
  );
}
