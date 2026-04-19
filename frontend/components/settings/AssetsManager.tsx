"use client";

import { Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAssets } from "@/lib/assets";

export function AssetsManager() {
  const { list, add, remove, ready } = useAssets();
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState("");
  const [version, setVersion] = useState("");

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const v = vendor.trim();
    const p = product.trim();
    if (!v || !p) return;
    add({ vendor: v, product: p, version: version.trim() || undefined });
    setVendor("");
    setProduct("");
    setVersion("");
  };

  return (
    <div className="space-y-4 rounded-lg border border-neutral-800 bg-surface-1 p-5">
      <form onSubmit={onSubmit} className="grid gap-2 sm:grid-cols-[1fr_1fr_120px_auto]">
        <Input
          value={vendor}
          onChange={(e) => setVendor(e.target.value)}
          placeholder="벤더 (예: microsoft)"
          autoComplete="off"
        />
        <Input
          value={product}
          onChange={(e) => setProduct(e.target.value)}
          placeholder="제품 (예: windows_11)"
          autoComplete="off"
        />
        <Input
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          placeholder="버전 (선택)"
          autoComplete="off"
        />
        <Button type="submit" disabled={!vendor.trim() || !product.trim()}>
          <Plus className="mr-1 h-4 w-4" /> 추가
        </Button>
      </form>

      {ready && list.length === 0 ? (
        <p className="text-xs text-neutral-500">
          아직 등록된 자산이 없습니다. 벤더와 제품명은 CPE 형식(<code>vendor:product</code>)을
          따릅니다. 예: <code>apache:log4j</code>, <code>microsoft:windows_11</code>.
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
                  <span className="ml-2 font-mono text-xs text-neutral-500">{a.version}</span>
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
