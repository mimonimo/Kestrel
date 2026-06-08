import { Card, CardContent, CardHeader } from "@/components/ui/card";

// 로딩 자리표시자. 막대 색은 ``bg-neutral-200 dark:bg-surface-2`` —
// 라이트/다크 양쪽 변형을 모두 줘야 한다(다른 스켈레톤과 동일 컨벤션).
// 예전엔 ``bg-neutral-800`` 단일값이라 라이트 테마에서 태그 자리표시자가
// 검정 박스로 떠 카드/태그가 "검게" 보이는 문제가 있었다.
const BAR = "rounded bg-neutral-200 dark:bg-surface-2";

export function CveListSkeleton({ count = 6 }: { count?: number }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {Array.from({ length: count }).map((_, i) => (
        <Card key={i} className="animate-pulse">
          <CardHeader className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3">
              <div className={`h-4 w-28 ${BAR}`} />
              <div className={`h-4 w-20 ${BAR}`} />
            </div>
            <div className={`h-5 w-3/4 ${BAR}`} />
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className={`h-4 w-full ${BAR}`} />
            <div className={`h-4 w-5/6 ${BAR}`} />
            <div className="flex gap-2">
              <div className={`h-5 w-12 ${BAR}`} />
              <div className={`h-5 w-16 ${BAR}`} />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
