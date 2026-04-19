import { AlertTriangle, SearchX } from "lucide-react";

export function EmptyState({ message = "조건에 맞는 취약점이 없습니다. 필터를 조정해 보세요." }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <SearchX className="h-10 w-10 text-neutral-600 mb-3" />
      <p className="text-sm text-neutral-500">{message}</p>
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <AlertTriangle className="h-10 w-10 text-red-500/80 mb-3" />
      <p className="text-sm text-neutral-300 mb-1">데이터를 불러오지 못했습니다.</p>
      <p className="text-xs text-neutral-500 max-w-md break-all">{error.message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-4 text-xs text-neutral-300 underline hover:text-neutral-100"
        >
          다시 시도
        </button>
      )}
    </div>
  );
}
