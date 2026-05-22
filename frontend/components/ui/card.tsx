import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

// Base card surface — paired light/dark. Static container by default
// (CVE 상세 페이지의 정보 카드처럼 클릭하지 않는 컨테이너는 hover 시
// 움직이면 오히려 불편). 클릭 가능한 카드 (CveListItem 등) 는 className
// 으로 `group hover:-translate-y-0.5 hover:shadow-md ...` 를 추가해
// 개별 opt-in 한다.
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-lg border border-neutral-200 bg-white transition-colors duration-150",
        "dark:border-neutral-800 dark:bg-surface-1",
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-5 pb-3", className)} {...props} />;
}

export function CardContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-5 pt-0", className)} {...props} />;
}

export function CardFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "border-t border-neutral-200 p-5 pt-3 dark:border-neutral-800",
        className,
      )}
      {...props}
    />
  );
}
