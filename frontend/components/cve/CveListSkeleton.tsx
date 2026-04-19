import { Card, CardContent, CardHeader } from "@/components/ui/card";

export function CveListSkeleton({ count = 6 }: { count?: number }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {Array.from({ length: count }).map((_, i) => (
        <Card key={i} className="animate-pulse">
          <CardHeader className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3">
              <div className="h-4 w-28 rounded bg-neutral-800" />
              <div className="h-4 w-20 rounded bg-neutral-800" />
            </div>
            <div className="h-5 w-3/4 rounded bg-neutral-800" />
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="h-4 w-full rounded bg-neutral-800" />
            <div className="h-4 w-5/6 rounded bg-neutral-800" />
            <div className="flex gap-2">
              <div className="h-5 w-12 rounded bg-neutral-800" />
              <div className="h-5 w-16 rounded bg-neutral-800" />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
