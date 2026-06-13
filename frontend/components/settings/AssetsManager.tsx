"use client";

import { Plus, Trash2, Search, Loader2, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAssets } from "@/lib/assets";
import { useDebounce } from "@/hooks/useDebounce";
import { api } from "@/lib/api";
import { useBodyScrollLock } from "@/lib/use-body-scroll-lock";
import { cn } from "@/lib/utils";

const OS_LABEL: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  android: "Android",
  ios: "iOS",
  other: "기타",
};

type AddFn = (a: { vendor: string; product: string; version?: string }) => void;

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
  const { list, remove, ready } = useAssets();
  const [modalOpen, setModalOpen] = useState(false);

  return (
    <div className="space-y-4 rounded-lg border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs text-neutral-500 dark:text-neutral-500">
          등록된 자산 <span className="font-semibold text-neutral-800 dark:text-neutral-200">{list.length}</span>개
        </span>
        <Button type="button" size="sm" onClick={() => setModalOpen(true)} className="gap-1.5">
          <Plus className="h-3.5 w-3.5" /> 자산 등록
        </Button>
      </div>

      {ready && list.length === 0 ? (
        <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-3 py-6 text-center text-xs text-neutral-600 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
          아직 등록된 자산이 없습니다. <span className="font-medium">자산 등록</span>으로 사용 중인 벤더·제품을 추가하세요.
        </p>
      ) : (
        <ul className="divide-y divide-neutral-200 rounded-lg border border-neutral-200 bg-white dark:divide-neutral-800 dark:border-neutral-800 dark:bg-surface-0">
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
                className="rounded p-1 text-red-600 hover:bg-red-500/10 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </li>
          ))}
        </ul>
      )}

      {modalOpen && <AssetRegisterModal onClose={() => setModalOpen(false)} />}
    </div>
  );
}

type RegisterMode = "search" | "browse" | "manual";

const MODE_TABS: { value: RegisterMode; label: string }[] = [
  { value: "search", label: "검색" },
  { value: "browse", label: "A-Z 둘러보기" },
  { value: "manual", label: "수동 입력" },
];

function AssetRegisterModal({ onClose }: { onClose: () => void }) {
  const { add } = useAssets();
  const [mode, setMode] = useState<RegisterMode>("search");
  useBodyScrollLock(true);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="자산 등록"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-neutral-950/60 px-4 py-12 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="relative flex max-h-[88vh] w-full max-w-2xl flex-col rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex shrink-0 items-center gap-2 border-b border-neutral-200 px-5 py-4 dark:border-neutral-800">
          <Plus className="h-4 w-4 text-sky-700 dark:text-sky-300" />
          <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">자산 등록</h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="닫기"
            className="ml-auto inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
          >
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <p className="text-[11px] text-neutral-600 dark:text-neutral-500">
            사용 중인 벤더·제품을 등록하면 영향받는 CVE 만 추려서 알려드립니다.
          </p>
          <div className="inline-flex flex-wrap gap-1.5">
            {MODE_TABS.map((t) => (
              <button
                key={t.value}
                type="button"
                onClick={() => setMode(t.value)}
                className={cn(
                  "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
                  mode === t.value
                    ? "border-sky-400 bg-sky-100 text-sky-800 dark:border-sky-500/50 dark:bg-sky-500/20 dark:text-sky-200"
                    : "border-neutral-300 text-neutral-600 hover:border-sky-300 hover:text-sky-700 dark:border-neutral-700 dark:text-neutral-400 dark:hover:text-sky-200",
                )}
              >
                {t.label}
              </button>
            ))}
          </div>
          {mode === "search" && <CatalogSearch add={add} />}
          {mode === "browse" && <BrowseEntry add={add} />}
          {mode === "manual" && <ManualEntry add={add} />}
        </div>
      </div>
    </div>
  );
}

// ─── 카탈로그 검색 등록 ──────────────────────────────────
function CatalogSearch({ add }: { add: AddFn }) {
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
    add({ vendor: selected.vendor, product: selected.product, version: version.trim() || undefined });
    setSelected(null);
    setQuery("");
    setVersion("");
  };

  const versionOptions = selected?.sampleVersions ?? [];

  return (
    <div className="space-y-2">
      <div className="grid gap-2 sm:grid-cols-[1fr_160px_auto]">
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
              placeholder="벤더·제품 검색 (예: chrome, log4j)"
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
                                className="rounded-full bg-slate-200 px-1.5 py-px text-[9px] font-medium text-slate-800 dark:bg-slate-500/25 dark:text-slate-100"
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
                  {isFetching ? "검색 중…" : "일치하는 제품이 없습니다. 아래에서 직접 입력하세요."}
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
              className="block h-10 w-full rounded-lg border border-neutral-200 bg-neutral-50 px-3 text-sm text-neutral-900 focus:border-sky-500 focus:outline-none dark:border-neutral-800 dark:bg-surface-2 dark:text-neutral-100"
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
    </div>
  );
}

// ─── 수동 입력 ───────────────────────────────────────────
function ManualEntry({ add }: { add: AddFn }) {
  const [manual, setManual] = useState("");
  const parts = manual.split(":").map((s) => s.trim()).filter(Boolean);
  // 최소 1개 토큰(벤더)만 있으면 OK — 제품 생략 시 모든 제품(*) 으로 간주.
  const valid = parts.length >= 1;

  // 미리보기 — 실제 등록될 vendor:product 형태.
  const preview = valid
    ? `${parts[0]}:${parts[1] ?? "*"}${parts[2] ? ` (버전 ${parts.slice(2).join(":")})` : ""}`
    : null;

  const onAdd = () => {
    if (!valid) return;
    const [vendor, product, ...rest] = parts;
    add({
      vendor,
      product: product ?? "*",
      version: rest.length > 0 ? rest.join(":") : undefined,
    });
    setManual("");
  };

  return (
    <div className="rounded-lg border border-neutral-200 bg-neutral-50 p-3 dark:border-neutral-800 dark:bg-surface-2/50">
      <p className="mb-2 text-[11px] font-medium text-neutral-700 dark:text-neutral-300">
        수동 입력
      </p>
      <div className="flex gap-2">
        <Input
          value={manual}
          onChange={(e) => setManual(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              onAdd();
            }
          }}
          placeholder="vendor:product[:version] — 예: google:chrome, goo*, nginx:nginx:1.24"
          autoComplete="off"
        />
        <Button type="button" onClick={onAdd} disabled={!valid} variant="outline">
          <Plus className="mr-1 h-4 w-4" /> 추가
        </Button>
      </div>
      {preview && (
        <p className="mt-1.5 text-[11px] text-sky-700 dark:text-sky-300">
          등록 예정: <span className="font-mono">{preview}</span>
        </p>
      )}
      <ul className="mt-2 space-y-0.5 text-[10px] leading-relaxed text-neutral-500 dark:text-neutral-500">
        <li>· 형식: <span className="font-mono">벤더:제품</span> 또는 <span className="font-mono">벤더:제품:버전</span> (콜론 구분)</li>
        <li>· 와일드카드 <span className="font-mono">*</span> 지원 — <span className="font-mono">goo*</span> = goo 로 시작하는 모든 벤더, <span className="font-mono">google:chr*</span> = chr 로 시작하는 제품</li>
        <li>· 제품 생략 시 해당 벤더의 <span className="font-mono">모든 제품(*)</span> 으로 등록 (예: <span className="font-mono">apache</span> → <span className="font-mono">apache:*</span>)</li>
        <li>· 대소문자는 매칭 시 무시됩니다 — 카탈로그에 없는 사내 제품도 등록 가능</li>
      </ul>
    </div>
  );
}

// ─── A-Z 둘러보기 (벤더 → 제품) ──────────────────────────
const AZ_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("").concat(["#"]);

function BrowseEntry({ add }: { add: AddFn }) {
  const [letter, setLetter] = useState<string>("A");
  const [vendor, setVendor] = useState<string | null>(null);
  const [added, setAdded] = useState<string | null>(null);

  const vendorsQ = useQuery({
    queryKey: ["asset-vendors", letter],
    queryFn: () => api.listAssetVendors(letter),
    enabled: !vendor,
    staleTime: 5 * 60_000,
  });
  const productsQ = useQuery({
    queryKey: ["asset-products", vendor],
    queryFn: () => api.listAssetProducts(vendor as string),
    enabled: !!vendor,
    staleTime: 5 * 60_000,
  });

  const onPickProduct = (product: string) => {
    if (!vendor) return;
    add({ vendor, product });
    setAdded(`${vendor}:${product}`);
    window.setTimeout(() => setAdded(null), 2500);
  };

  return (
    <div className="space-y-3">
      {/* A-Z */}
      <div className="flex flex-wrap gap-1">
        {AZ_LETTERS.map((l) => (
          <button
            key={l}
            type="button"
            onClick={() => {
              setLetter(l);
              setVendor(null);
            }}
            className={cn(
              "h-6 w-6 rounded text-[11px] font-medium tabular-nums transition-colors",
              letter === l && !vendor
                ? "bg-sky-500 text-white"
                : "bg-neutral-200 text-neutral-600 hover:bg-neutral-300 dark:bg-surface-2 dark:text-neutral-400 dark:hover:bg-surface-3",
            )}
          >
            {l}
          </button>
        ))}
      </div>

      {added && (
        <p className="text-[11px] text-emerald-700 dark:text-emerald-300">
          <span className="font-mono">{added}</span> 등록됨
        </p>
      )}

      {!vendor ? (
        <BrowseList
          q={vendorsQ}
          empty="이 글자로 시작하는 벤더가 없습니다."
          render={(items: { vendor: string; cveCount: number }[]) => (
            <ul className="divide-y divide-neutral-100 dark:divide-neutral-800">
              {items.map((v) => (
                <li key={v.vendor}>
                  <button
                    type="button"
                    onClick={() => setVendor(v.vendor)}
                    className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm transition-colors hover:bg-neutral-100 dark:hover:bg-surface-3"
                  >
                    <span className="truncate font-mono text-neutral-900 dark:text-neutral-100">
                      {v.vendor}
                    </span>
                    <span className="shrink-0 text-[11px] text-neutral-500">
                      CVE {v.cveCount.toLocaleString("ko-KR")}건
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        />
      ) : (
        <div>
          <button
            type="button"
            onClick={() => setVendor(null)}
            className="mb-2 inline-flex items-center gap-1 text-[11px] text-neutral-500 hover:text-sky-700 dark:hover:text-sky-300"
          >
            ← 벤더 목록 · <span className="font-mono text-neutral-700 dark:text-neutral-300">{vendor}</span>
          </button>
          <BrowseList
            q={productsQ}
            empty="제품이 없습니다."
            render={(items: { product: string; cveCount: number; osFamilies: string[] }[]) => (
              <ul className="divide-y divide-neutral-100 dark:divide-neutral-800">
                {items.map((p) => (
                  <li key={p.product}>
                    <button
                      type="button"
                      onClick={() => onPickProduct(p.product)}
                      className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm transition-colors hover:bg-neutral-100 dark:hover:bg-surface-3"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-mono text-neutral-900 dark:text-neutral-100">
                          {p.product}
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1">
                          {p.osFamilies.map((os) => (
                            <span
                              key={os}
                              className="rounded-full bg-slate-200 px-1.5 py-px text-[9px] font-medium text-slate-800 dark:bg-slate-500/25 dark:text-slate-100"
                            >
                              {OS_LABEL[os] ?? os}
                            </span>
                          ))}
                          <span className="text-[11px] text-neutral-500">
                            CVE {p.cveCount.toLocaleString("ko-KR")}건
                          </span>
                        </div>
                      </div>
                      <span className="shrink-0 rounded bg-sky-500/10 px-1.5 py-0.5 text-[11px] text-sky-700 dark:text-sky-300">
                        추가
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          />
        </div>
      )}
    </div>
  );
}

function BrowseList<T>({
  q,
  empty,
  render,
}: {
  q: { isPending: boolean; isError: boolean; data?: { items: T[] } };
  empty: string;
  render: (items: T[]) => React.ReactNode;
}) {
  const items = q.data?.items ?? [];
  if (q.isPending)
    return (
      <p className="flex items-center gap-2 px-1 py-4 text-xs text-neutral-500">
        <Loader2 className="h-3 w-3 animate-spin" /> 불러오는 중…
      </p>
    );
  if (q.isError)
    return <p className="px-1 py-4 text-xs text-rose-700 dark:text-rose-300">불러오지 못했습니다.</p>;
  if (items.length === 0)
    return <p className="px-1 py-4 text-xs text-neutral-500">{empty}</p>;
  return (
    <div className="max-h-72 overflow-y-auto rounded-lg border border-neutral-200 dark:border-neutral-800">
      {render(items)}
    </div>
  );
}
