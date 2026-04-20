"use client";

import { Plus, Trash2, Search, Loader2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAssets } from "@/lib/assets";
import { useDebounce } from "@/hooks/useDebounce";
import { api, type AssetCatalogEntry } from "@/lib/api";
import { cn } from "@/lib/utils";

const OS_LABEL: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  android: "Android",
  ios: "iOS",
  other: "기타",
};

export function AssetsManager() {
  const { list, add, remove, ready } = useAssets();
  const [query, setQuery] = useState("");
  const debounced = useDebounce(query, 200);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<AssetCatalogEntry | null>(null);
  const [version, setVersion] = useState("");
  const wrapperRef = useRef<HTMLDivElement>(null);

  const { data, isFetching } = useQuery({
    queryKey: ["asset-catalog", debounced],
    queryFn: () => api.searchAssetCatalog(debounced, 20),
    enabled: open && debounced.trim().length > 0,
    staleTime: 30_000,
  });

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!wrapperRef.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", handler);
    return () => window.removeEventListener("mousedown", handler);
  }, []);

  const choose = (entry: AssetCatalogEntry) => {
    setSelected(entry);
    setQuery(`${entry.vendor}:${entry.product}`);
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
    <div className="space-y-4 rounded-lg border border-neutral-800 bg-surface-1 p-5">
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
            <div className="absolute z-20 mt-1 max-h-72 w-full overflow-y-auto rounded-md border border-neutral-700 bg-surface-2 shadow-xl">
              {data && data.items.length > 0 ? (
                <ul className="divide-y divide-neutral-800">
                  {data.items.map((item) => (
                    <li key={`${item.vendor}:${item.product}:${item.osFamily}`}>
                      <button
                        type="button"
                        onClick={() => choose(item)}
                        className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm hover:bg-neutral-800/60"
                      >
                        <div className="min-w-0">
                          <div className="truncate font-mono text-neutral-100">
                            {item.vendor}
                            <span className="text-neutral-500">:</span>
                            {item.product}
                          </div>
                          <div className="mt-0.5 text-[11px] text-neutral-500">
                            {OS_LABEL[item.osFamily] ?? item.osFamily} · CVE {item.cveCount}건
                          </div>
                        </div>
                        <span className="shrink-0 rounded bg-sky-500/10 px-1.5 py-0.5 text-[11px] text-sky-300">
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
              className="block h-10 w-full rounded-md border border-neutral-800 bg-surface-2 px-3 text-sm text-neutral-100 focus:border-neutral-600 focus:outline-none"
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
        <p className="text-xs text-sky-300">
          선택됨: <span className="font-mono">{selected.vendor}:{selected.product}</span>{" "}
          <span className="text-neutral-500">
            ({OS_LABEL[selected.osFamily] ?? selected.osFamily}) · CVE {selected.cveCount}건
          </span>
        </p>
      )}

      {ready && list.length === 0 ? (
        <p className="text-xs text-neutral-500">
          위 검색창에서 사용 중인 벤더·제품을 선택해 추가하세요. 파싱된 CPE 카탈로그에서만
          고를 수 있어 매칭 정확도가 보장됩니다.
        </p>
      ) : (
        <ul className="divide-y divide-neutral-800 rounded-md border border-neutral-800 bg-surface-0">
          {list.map((a) => (
            <li key={a.id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
              <div className="min-w-0 flex-1">
                <span className="font-mono text-neutral-100">
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
                className="rounded p-1 text-red-400 hover:bg-red-500/10 hover:text-red-300"
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
