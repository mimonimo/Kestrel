import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { SortKey } from "@/lib/sort";
import type { SearchFilters } from "@/lib/types";

export function useCveSearch(
  filters: SearchFilters,
  page = 1,
  pageSize = 20,
  sort: SortKey = "newest",
) {
  return useQuery({
    queryKey: ["search", filters, page, pageSize, sort],
    queryFn: () => api.searchVulnerabilities(filters, page, pageSize, sort),
    placeholderData: keepPreviousData,
  });
}
