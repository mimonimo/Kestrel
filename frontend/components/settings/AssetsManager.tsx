"use client";

import { Plus, Trash2, Search, Loader2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAssets } from "@/lib/assets";
import { useDebounce } from "@/hooks/useDebounce";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

const OS_LABEL: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  android: "Android",
  ios: "iOS",
  other: "기타",
};

// 같은 제품이 OS·대소문자별로 여러 행으로 쪼개져 오던 카탈로그를
// vendor:product 기준(대소문자 무시)으로 묶은 표시 단위.
interface CatalogGroup {
  vendor: string;
  product: string;
  cveCount: number;
  osFamilies: string[];
  sampleVersions: string[];
}

export function AssetsManager() {
  const { list, add, remove, ready } = useAssets();
  const [query, setQuery] = useState("");
  const debounced = useDebounce(query, 200);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<CatalogGroup | null>(null);
  const [version, setVersion] = useState("");
  const wrapperRef = useRef<HTMLDivElement>(null);

  const { data, isFetching } = useQuery({
    queryKey: ["asset-catalog", debounced],
    queryFn: () => api.searchAssetCatalog(debounced, 40),
    enabled: open && debounced.trim().length > 0,
    staleTime: 30_000,
  });

  // OS·대소문자 중복을 vendor:product 로 병합 — OS 는 칩, CVE 는 합산,
  // 대표 표기는 CVE 가 가장 많은 변형의 원래 대소문자를 사용.
  const groups = useMemo<CatalogGroup[]>(() => {
    const map = new Map<
      string,
      CatalogGroup & { _bestCount: number; _os: Set<string>; _ver: Set<string> }
    >();
    for (const it of data?.items ?? []) {
      const key = `${it.vendor.toLowerCase()}:${it.product.toLowerCase()}`;
      let g = map.get(key);
      if (!g) {
        g = {
          vendor: it.vendor,
          product: it.product,
          cveCount: 0,
          osFamilies: [],
          sampleVersions: [],
          _bestCount: -1,
          _os: new Set<string>(),
          _ver: new Set<string>(),
        };
        map.set(key, g);
      }
      g.cveCount += it.cveCount;
      if (it.osFamily) g._os.add(it.osFamily);
      (it.sampleVersions ?? []).forEach((v) => g!._ver.add(v));
      if (it.cveCount > g._bestCount) {
        g._bestCount = it.cveCount;
        g.vendor = it.vendor;
        g.product = it.product;
      }
    }
    return [...map.values()]
      .map((g) => ({
        vendor: g.vendor,
        product: g.product,
        cveCount: g.cveCount,
        osFamilies: [...g._os],
        sampleVersions: [...g._ver],
      }))
      .sort((a, b) => b.cveCount - a.cveCount);
  }, [data]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!wrapperRef.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", handler);
    return () => window.removeEventListener("mousedown", handler);
  }, []);

  const choose = (g: CatalogGroup) => {
    setSelected(g);
    setQuery(`${g.vendor}:${g.product}`);
    setVersion("");
    setOpen(false);
  };

  const onAdd = () => {
    if (!selected) return;
    add({
      vendor: selected.vendor,
      product: selected.product,
      version: version.trim() || undefined,
    });
    setSelected(null);
    setQuery("");
    setVersion("");
  };

  const versionOptions = useMemo(() => selected?.sampleVersions ?? [], [selected]);

  return (
    <div className="space-y-4 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-surface-1 p-5">
      <div className="grid gap-2 sm:grid-cols-[1fr_180px_auto]">
        <div ref={wrapperRef} className="relative">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-neutral-500" />
            <Input
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setSelected(null);
                setOpen(true);
              }}
              onFocus={() => setOpen(true)}
              placeholder="벤더 또는 제품명을 검색 (예: microsoft, chrome, log4j)"
              autoComplete="off"
              className="pl-8"
            />
            {isFetching && (
              <Loader2 className="absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 animate-spin text-neutral-500" />
            )}
          </div>
          {open && debounced.trim().length > 0 && (
            <div className="absolute z-20 mt-1 max-h-72 w-full overflow-y-auto rounded-lg border border-neutral-200 bg-white shadow-xl dark:border-neutral-700 dark:bg-surface-2">
              {groups.length > 0 ? (
                <ul className="divide-y divide-neutral-100 dark:divide-neutral-800">
                  {groups.map((g) => (
                    <li key={`${g.vendor}:${g.product}`}>
                      <button
                        type="button"
                        onClick={() => choose(g)}
                        className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm transition-colors hover:bg-neutral-100 dark:hover:bg-surface-3"
                      >
                        <div className="min-w-0">
                          <div className="truncate font-mono text-neutral-900 dark:text-neutral-100">
                            {g.vendor}
                            <span className="text-neutral-500">:</span>
                            {g.product}
                          </div>
                          <div className="mt-1 flex flex-wrap items-center gap-1">
                            {g.osFamilies.map((os) => (
                              <span
                                key={os}
                                className="rounded-full bg-neutral-100 px-1.5 py-px text-[9px] font-medium text-neutral-600 dark:bg-surface-3 dark:text-neutral-300"
                              >
                                {OS_LABEL[os] ?? os}
                              </span>
                            ))}
                            <span className="text-[11px] text-neutral-500">
                              CVE {g.cveCount.toLocaleString("ko-KR")}건
                            </span>
                          </div>
                        </div>
                        <span className="shrink-0 rounded bg-sky-500/10 px-1.5 py-0.5 text-[11px] text-sky-700 dark:text-sky-300">
                          선택
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="px-3 py-4 text-center text-xs text-neutral-500">
                  {isFetching ? "검색 중…" : "일치하는 제품이 없습니다."}
                </div>
              )}
            </div>
          )}
        </div>

        <div>
          {versionOptions.length > 0 ? (
            <select
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              className="block h-10 w-full rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-surface-2 px-3 text-sm text-neutral-900 dark:text-neutral-100 focus:border-sky-500 focus:outline-none"
            >
              <option value="">버전 (전체)</option>
              {versionOptions.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          ) : (
            <Input
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="버전 (선택)"
              autoComplete="off"
              disabled={!selected}
            />
          )}
        </div>

        <Button type="button" onClick={onAdd} disabled={!selected}>
          <Plus className="mr-1 h-4 w-4" /> 추가
        </Button>
      </div>

      {selected && (
        <p className="text-xs text-sky-700 dark:text-sky-300">
          선택됨: <span className="font-mono">{selected.vendor}:{selected.product}</span>{" "}
          <span className="text-neutral-500">
            ({selected.osFamilies.map((os) => OS_LABEL[os] ?? os).join(", ") || "전체"}) · CVE{" "}
            {selected.cveCount.toLocaleString("ko-KR")}건
          </span>
        </p>
      )}

      {ready && list.length === 0 ? (
        <p className="text-xs text-neutral-500">
          위 검색창에서 사용 중인 벤더·제품을 선택해 추가하세요. 파싱된 CPE 카탈로그에서만
          고를 수 있어 매칭 정확도가 보장됩니다.
        </p>
      ) : (
        <ul className="divide-y divide-neutral-200 dark:divide-neutral-800 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-surface-0">
          {list.map((a) => (
            <li key={a.id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
              <div className="min-w-0 flex-1">
                <span className="font-mono text-neutral-900 dark:text-neutral-100">
                  {a.vendor}:{a.product}
                </span>
                {a.version && (
                  <span className={cn("ml-2 font-mono text-xs text-neutral-500")}>{a.version}</span>
                )}
              </div>
              <button
                type="button"
                onClick={() => remove(a.id)}
                aria-label="자산 삭제"
                className="rounded p-1 text-red-600 dark:text-red-400 hover:bg-red-500/10 hover:text-red-700 dark:hover:text-red-300"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
