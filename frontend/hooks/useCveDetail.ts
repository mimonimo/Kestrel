import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useCveDetail(cveId: string) {
  return useQuery({
    queryKey: ["cve", cveId],
    queryFn: () => api.getVulnerability(cveId),
    enabled: !!cveId,
  });
}
