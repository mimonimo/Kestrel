import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronLeft, AlertTriangle } from "lucide-react";
import { CveDetail } from "@/components/cve/CveDetail";
import { fetchCveServer, ServerApiError } from "@/lib/server-api";

interface Props {
  params: Promise<{ id: string }>;
}

export async function generateMetadata({ params }: Props) {
  const { id } = await params;
  try {
    const vuln = await fetchCveServer(decodeURIComponent(id));
    if (!vuln) return { title: "CVE Not Found — Kestrel" };
    return {
      title: `${vuln.cveId} — ${vuln.title}`,
      description: vuln.summary ?? vuln.title,
    };
  } catch {
    return { title: "Kestrel" };
  }
}

export default async function CveDetailPage({ params }: Props) {
  const { id } = await params;
  const cveId = decodeURIComponent(id);

  let vuln: Awaited<ReturnType<typeof fetchCveServer>> = null;
  let fetchError: Error | null = null;
  try {
    vuln = await fetchCveServer(cveId);
  } catch (err) {
    fetchError = err as Error;
  }

  if (!fetchError && !vuln) notFound();

  return (
    <div className="mx-auto max-w-7xl px-6">
      <Link
        href="/"
        className="inline-flex items-center gap-1 text-sm text-neutral-400 hover:text-neutral-100 mt-6"
      >
        <ChevronLeft className="h-4 w-4" />
        대시보드로 돌아가기
      </Link>
      {fetchError ? (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <AlertTriangle className="h-10 w-10 text-red-500/80 mb-3" />
          <p className="text-sm text-neutral-300 mb-1">상세 정보를 불러오지 못했습니다.</p>
          <p className="text-xs text-neutral-500 max-w-md break-all">
            {fetchError instanceof ServerApiError
              ? `서버 응답: ${fetchError.status}`
              : fetchError.message}
          </p>
        </div>
      ) : (
        vuln && <CveDetail vuln={vuln} />
      )}
    </div>
  );
}
