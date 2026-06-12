"use client";

// 연관 취약점 force-directed 그래프 — 경량 물리 시뮬레이션(외부 라이브러리 없음).
// 노드끼리 밀어내며 자연스럽게 퍼지고(겹침 방지), 드래그로 옮길 수 있다.
// 중심=현재 CVE 고정. 관계 유형별 색상 + 심각도별 크기. 클릭 시 이동.
// 데스크톱=그래프, 모바일=리스트 폴백(반응형).
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import type { Route } from "next";

import type { RelatedCve } from "@/lib/types";

interface Cat { label: string; hex: string }
const CATS: Record<string, Cat> = {
  product: { label: "연관 제품·벤더", hex: "#10b981" },
  weakness_high: { label: "상위 약점(더 위험)", hex: "#f43f5e" },
  weakness_low: { label: "하위 약점", hex: "#0ea5e9" },
  weakness: { label: "공통 약점", hex: "#6366f1" },
  related: { label: "기타 연관", hex: "#94a3b8" },
};
function catOf(relation?: string): Cat {
  if (relation === "product" || relation === "vendor") return CATS.product;
  return (relation && CATS[relation]) || CATS.related;
}
// 범례에 노출할 순서.
const LEGEND_CATS = ["product", "weakness_high", "weakness", "weakness_low", "related"];
// 심각도 → 글자/알약 크기.
function fontOf(sev?: string | null): number {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return 13;
  if (s === "high") return 12;
  return 11;
}
// 라벨 픽셀 폭 추정(한글은 넓게).
function labelWidth(text: string, fs: number): number {
  let w = 0;
  for (const ch of text) w += /[ -~]/.test(ch) ? fs * 0.58 : fs * 1.02;
  return w;
}

const VW = 600;
const VH = 280;
const CX = VW / 2;
const CY = VH / 2;

interface Sim {
  it: RelatedCve;
  x: number;
  y: number;
  vx: number;
  vy: number;
  hw: number; // half width
  fs: number;
  cat: Cat;
  phase: number;
}

export function RelatedCvesGraph({ centerId, items }: { centerId: string; items: RelatedCve[] }) {
  const router = useRouter();
  const svgRef = useRef<SVGSVGElement | null>(null);
  const nodesRef = useRef<Sim[]>([]);
  const alphaRef = useRef(1);
  const rafRef = useRef<number | null>(null);
  const dragRef = useRef<{ i: number; moved: boolean } | null>(null);
  const tickRef = useRef<() => void>(() => {});
  const [, setFrame] = useState(0);

  // 노드 초기화(items 변경 시).
  useEffect(() => {
    const n = Math.max(items.length, 1);
    nodesRef.current = items.map((it, i) => {
      const fs = fontOf(it.severity);
      const hw = labelWidth(it.cveId, fs) / 2 + 12;
      const a = (i / n) * Math.PI * 2 - Math.PI / 2;
      return {
        it,
        x: CX + 96 * Math.cos(a) + (Math.random() - 0.5) * 16,
        y: CY + 66 * Math.sin(a) + (Math.random() - 0.5) * 16,
        vx: 0,
        vy: 0,
        hw,
        fs,
        cat: catOf(it.relation),
        phase: Math.random() * Math.PI * 2,
      };
    });
    alphaRef.current = 1;

    const LINK = 104;
    const LINK_K = 0.06;
    const REP = 3000;
    const DAMP = 0.86;
    const PAD = 6;

    const tick = () => {
      const nodes = nodesRef.current;
      const drag = dragRef.current;
      const alpha = alphaRef.current;
      for (let i = 0; i < nodes.length; i++) {
        if (drag && drag.i === i) continue; // 드래그 중인 노드는 물리 적용 안 함
        const a = nodes[i];
        let fx = 0;
        let fy = 0;
        // 중심과의 스프링(고리 거리 유지)
        const dcx = CX - a.x;
        const dcy = CY - a.y;
        const dc = Math.hypot(dcx, dcy) || 0.01;
        const sp = (dc - LINK) * LINK_K;
        fx += (dcx / dc) * sp;
        fy += (dcy / dc) * sp;
        // 다른 노드와 반발 + 충돌
        for (let j = 0; j < nodes.length; j++) {
          if (i === j) continue;
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const d = Math.hypot(dx, dy) || 0.01;
          fx += (dx / d) * (REP / (d * d));
          fy += (dy / d) * (REP / (d * d));
          const minD = a.hw + b.hw + 6;
          if (d < minD) {
            const push = (minD - d) * 0.5;
            fx += (dx / d) * push;
            fy += (dy / d) * push;
          }
        }
        // 중심 노드 회피
        const dCenter = Math.hypot(a.x - CX, a.y - CY) || 0.01;
        if (dCenter < 38 + a.hw * 0.2) {
          fx += ((a.x - CX) / dCenter) * (38 - dCenter) * 0.6;
          fy += ((a.y - CY) / dCenter) * (38 - dCenter) * 0.6;
        }
        a.vx = (a.vx + fx * alpha) * DAMP;
        a.vy = (a.vy + fy * alpha) * DAMP;
        a.x = Math.max(a.hw + PAD, Math.min(VW - a.hw - PAD, a.x + a.vx));
        a.y = Math.max(14 + PAD, Math.min(VH - 14 - PAD, a.y + a.vy));
      }
      // 평소엔 정지. 상호작용(드래그) 중에만 활성 유지, 끝나면 부드럽게 감쇠 후 멈춤.
      alphaRef.current = drag ? Math.max(alpha, 0.5) : alpha * 0.92;
      setFrame((f) => f + 1);
      if (alphaRef.current > 0.012 || drag) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        alphaRef.current = 0;
        rafRef.current = null;
      }
    };
    tickRef.current = tick;
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [items]);

  const toLocal = (e: React.PointerEvent): { x: number; y: number } | null => {
    const svg = svgRef.current;
    if (!svg) return null;
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const ctm = svg.getScreenCTM();
    if (!ctm) return null;
    const loc = pt.matrixTransform(ctm.inverse());
    return { x: loc.x, y: loc.y };
  };

  const kick = (a: number) => {
    alphaRef.current = Math.max(alphaRef.current, a);
    if (rafRef.current == null) rafRef.current = requestAnimationFrame(tickRef.current);
  };

  const onDown = (i: number) => (e: React.PointerEvent) => {
    (e.target as Element).setPointerCapture?.(e.pointerId);
    dragRef.current = { i, moved: false };
    kick(0.6);
  };
  const onMove = (e: React.PointerEvent) => {
    const drag = dragRef.current;
    if (!drag) return;
    const loc = toLocal(e);
    if (!loc) return;
    const node = nodesRef.current[drag.i];
    if (!node) return;
    node.x = Math.max(node.hw + 8, Math.min(VW - node.hw - 8, loc.x));
    node.y = Math.max(24, Math.min(VH - 24, loc.y));
    node.vx = 0;
    node.vy = 0;
    drag.moved = true;
    kick(0.5);
    setFrame((f) => f + 1);
  };
  const onUp = (cveId: string) => (e: React.PointerEvent) => {
    const drag = dragRef.current;
    dragRef.current = null;
    (e.target as Element).releasePointerCapture?.(e.pointerId);
    if (drag && !drag.moved) {
      router.push(`/cve/${cveId}` as Route);
    } else {
      // 드래그 후 살짝 재가열해 주변 노드가 자연스럽게 정착.
      kick(0.4);
    }
  };

  const nodes = nodesRef.current;

  return (
    <div>
      <div className="mx-auto max-w-xl hidden sm:block">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${VW} ${VH}`}
          className="h-auto w-full touch-none select-none"
          onPointerMove={onMove}
          role="img"
          aria-label="연관 취약점 force 그래프"
        >
          {[120, 82, 46].map((r) => (
            <circle key={r} cx={CX} cy={CY} r={r} className="fill-neutral-500/[0.035]" />
          ))}
          {/* 링크 */}
          {nodes.map((nd) => (
            <line
              key={`l-${nd.it.cveId}`}
              x1={CX}
              y1={CY}
              x2={nd.x}
              y2={nd.y}
              stroke={nd.cat.hex}
              strokeWidth={1.5}
              strokeOpacity={0.5}
            />
          ))}
          {/* 중심 노드 */}
          <circle cx={CX} cy={CY} r={30} className="fill-sky-500/15" />
          <circle cx={CX} cy={CY} r={22} className="fill-sky-500" />
          <text x={CX} y={CY - 3} textAnchor="middle" className="fill-white" style={{ fontSize: 8 }}>
            현재
          </text>
          <text x={CX} y={CY + 7} textAnchor="middle" className="fill-white font-mono" style={{ fontSize: 8, fontWeight: 700 }}>
            {centerId.replace(/^CVE-/, "")}
          </text>
          {/* 노드 알약 */}
          {nodes.map((nd, i) => (
            <g
              key={nd.it.cveId}
              transform={`translate(${nd.x},${nd.y})`}
              className="cursor-pointer"
              onPointerDown={onDown(i)}
              onPointerUp={onUp(nd.it.cveId)}
            >
              <title>{`${nd.it.cveId} · ${nd.it.reason}${nd.it.cvssScore != null ? ` · CVSS ${nd.it.cvssScore}` : ""}\n${nd.it.title}`}</title>
              <rect
                x={-nd.hw}
                y={-11}
                width={nd.hw * 2}
                height={22}
                rx={11}
                ry={11}
                className="fill-white dark:fill-[#1c1c1f]"
                stroke={nd.cat.hex}
                strokeWidth={2}
              />
              {nd.it.kevListed && <circle cx={-nd.hw + 9} cy={0} r={3} fill="#f43f5e" />}
              <text
                textAnchor="middle"
                dy={nd.fs * 0.35}
                x={nd.it.kevListed ? 5 : 0}
                className="font-mono font-semibold"
                style={{ fontSize: nd.fs, fill: nd.cat.hex }}
              >
                {nd.it.cveId}
              </text>
            </g>
          ))}
        </svg>
        {/* 범례 */}
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-neutral-500 dark:text-neutral-400">
          {LEGEND_CATS.map((k) => CATS[k]).map((c) => (
            <span key={c.label} className="inline-flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: c.hex }} />
              {c.label}
            </span>
          ))}
          <span className="inline-flex items-center gap-1">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-rose-500" /> KEV
          </span>
          <span className="text-neutral-400 dark:text-neutral-500">· 크기=심각도 · 드래그로 이동 · 클릭 시 상세</span>
        </div>
      </div>

      {/* 모바일 리스트 폴백 */}
      <ul className="space-y-1.5 sm:hidden">
        {items.map((it) => {
          const c = catOf(it.relation);
          return (
            <li key={it.cveId}>
              <button
                type="button"
                onClick={() => router.push(`/cve/${it.cveId}` as Route)}
                className="flex w-full items-center gap-2 rounded-lg border border-neutral-200 bg-white px-2.5 py-1.5 text-left dark:border-neutral-800 dark:bg-surface-1"
              >
                <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: c.hex }} />
                <span className="font-mono text-[11px] font-semibold text-neutral-900 dark:text-neutral-100">{it.cveId}</span>
                {it.cvssScore != null && (
                  <span className="font-mono text-[10px] font-bold tabular-nums text-neutral-500">{it.cvssScore.toFixed(1)}</span>
                )}
                <span className="ml-auto rounded-full bg-surface-2 px-1.5 py-px text-[9px] text-neutral-500">{it.reason}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
