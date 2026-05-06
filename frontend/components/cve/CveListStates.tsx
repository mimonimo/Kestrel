import { RefreshCw, SearchX } from "lucide-react";

import { ErrorBox, FeedbackBoxButton } from "@/components/ui/feedback-box";

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
    <div className="py-8">
      <ErrorBox
        title="데이터를 불러오지 못했습니다"
        message={error.message}
        actions={
          onRetry ? (
            <FeedbackBoxButton onClick={onRetry}>
              <RefreshCw className="h-3 w-3" />
              다시 시도
            </FeedbackBoxButton>
          ) : undefined
        }
      />
    </div>
  );
}
