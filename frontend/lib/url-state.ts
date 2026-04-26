"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo } from "react";
import type { OsFamily, Severity, VulnType } from "./types";
import type { SortKey } from "./sort";
import type { FilterState } from "@/components/search/FilterPanel";
import { EMPTY_FILTERS } from "@/components/search/FilterPanel";

interface UrlState {
  query: string;
  filters: FilterState;
  page: number;
  sort: SortKey;
}

const SEV: Severity[] = ["critical", "high", "medium", "low"];
const OS: OsFamily[] = ["windows", "linux", "macos", "android", "ios", "other"];
const TYPE: VulnType[] = [
  "RCE",
  "XSS",
  "SQLi",
  "CSRF",
  "XXE",
  "SSRF",
  "LFI",
  "Path-Traversal",
  "Deserialization",
  "Open-Redirect",
  "Privilege-Escalation",
  "Info-Disclosure",
  "Memory-Corruption",
  "DoS",
  "Auth",
  "Other",
];
const SORT: SortKey[] = ["newest", "oldest", "severity", "cvss"];

function intersect<T extends string>(input: string[], allowed: readonly T[]): T[] {
  const set = new Set<T>(allowed);
  return input.filter((v): v is T => set.has(v as T));
}

function parseSort(raw: string | null): SortKey {
  return SORT.includes(raw as SortKey) ? (raw as SortKey) : "newest";
}

export function useUrlState(): UrlState & {
  set: (next: Partial<UrlState>) => void;
} {
  const router = useRouter();
  const params = useSearchParams();

  const state = useMemo<UrlState>(
    () => ({
      query: params.get("q") ?? "",
      filters: {
        severity: intersect(params.getAll("severity"), SEV),
        osFamily: intersect(params.getAll("os"), OS),
        types: intersect(params.getAll("type"), TYPE),
        fromDate: params.get("from") ?? "",
        toDate: params.get("to") ?? "",
      },
      page: Math.max(1, Number.parseInt(params.get("page") ?? "1", 10) || 1),
      sort: parseSort(params.get("sort")),
    }),
    [params],
  );

  const set = useCallback(
    (patch: Partial<UrlState>) => {
      const next: UrlState = {
        query: patch.query ?? state.query,
        filters: patch.filters ?? state.filters,
        page: patch.page ?? state.page,
        sort: patch.sort ?? state.sort,
      };

      const sp = new URLSearchParams();
      if (next.query) sp.set("q", next.query);
      next.filters.severity.forEach((s) => sp.append("severity", s));
      next.filters.osFamily.forEach((o) => sp.append("os", o));
      next.filters.types.forEach((t) => sp.append("type", t));
      if (next.filters.fromDate) sp.set("from", next.filters.fromDate);
      if (next.filters.toDate) sp.set("to", next.filters.toDate);
      if (next.page > 1) sp.set("page", String(next.page));
      if (next.sort && next.sort !== "newest") sp.set("sort", next.sort);

      const qs = sp.toString();
      router.replace(qs ? `/?${qs}` : "/", { scroll: false });
    },
    [state, router],
  );

  return { ...state, set };
}

export const NO_FILTERS: FilterState = EMPTY_FILTERS;
