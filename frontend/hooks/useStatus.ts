import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

// 60s 폴링 — 배너용. 너무 잦은 호출은 피하고, 토큰/수집 변동은 분 단위면 충분.
export function useStatus() {
  return useQuery({
    queryKey: ["status"],
    queryFn: () => api.getStatus(),
    refetchInterval: 60_000,
    staleTime: 30_000,
    retry: 0,
  });
}
