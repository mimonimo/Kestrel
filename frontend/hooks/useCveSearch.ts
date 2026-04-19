import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { SearchFilters } from "@/lib/types";

export function useCveSearch(filters: SearchFilters, page = 1, pageSize = 20) {
  return useQuery({
    queryKey: ["search", filters, page, pageSize],
    queryFn: () => api.searchVulnerabilities(filters, page, pageSize),
    placeholderData: keepPreviousData,
  });
}
