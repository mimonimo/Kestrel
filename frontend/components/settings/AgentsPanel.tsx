"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Loader2, Play, Plus, Power, Trash2 } from "lucide-react";

import { type Agent, type AgentInput, createAgent, deleteAgent, listAgents, runAgents, updateAgent } from "@/lib/api";
import { cn } from "@/lib/utils";

const KEY = ["agents"];

// 빠른 시작용 페르소나 프리셋 — 폼을 채워줄 뿐, 자유 편집 가능.
const PRESETS: { name: string; persona: string; emoji: string; prompt: string }[] = [
  {
    name: "공격 관점 분석가",
    persona: "레드팀 / 공격자",
    emoji: "⚔️",
    prompt: "당신은 공격자(레드팀) 관점의 분석가입니다. 익스플로잇 경로·공격 체인·우회 기법을 우선으로, 실제 악용 시나리오 중심으로 날카롭게 분석합니다.",
  },
  {
    name: "방어 관점 분석가",
    persona: "블루팀 / 방어자",
    emoji: "🛡️",
    prompt: "당신은 방어자(블루팀) 관점의 분석가입니다. 탐지 규칙·완화책·패치·설정 강화를 우선으로, 운영팀이 바로 적용할 대응을 중심으로 분석합니다.",
  },
  {
    name: "위협 인텔 전문가",
    persona: "위협 인텔리전스",
    emoji: "🔭",
    prompt: "당신은 위협 인텔리전스 전문가입니다. 실제 악용 동향(KEV)·공격 그룹·노출 범위·우선순위를 중심으로 거시적 위협 맥락을 분석합니다.",
  },
];

export function AgentsPanel() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: KEY, queryFn: listAgents, staleTime: 30_000 });

  const [form, setForm] = useState<AgentInput>({ name: "", persona: "", avatarEmoji: "🤖", personaPrompt: "", dailyLimit: 5 });
  const [err, setErr] = useState("");

  const create = useMutation({
    mutationFn: () => createAgent(form),
    onSuccess: () => {
      setForm({ name: "", persona: "", avatarEmoji: "🤖", personaPrompt: "", dailyLimit: 5 });
      setErr("");
      qc.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "생성 실패"),
  });
  const toggle = useMutation({
    mutationFn: (a: Agent) => updateAgent(a.id, { enabled: !a.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => deleteAgent(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
  const [runMsg, setRunMsg] = useState("");
  const run = useMutation({
    mutationFn: runAgents,
    onSuccess: (r) => setRunMsg(r.message),
    onError: (e) => setRunMsg(e instanceof Error ? e.message : "실행 실패"),
  });

  const applyPreset = (p: (typeof PRESETS)[number]) =>
    setForm((f) => ({ ...f, name: p.name, persona: p.persona, avatarEmoji: p.emoji, personaPrompt: p.prompt }));

  const agents = list.data ?? [];

  return (
    <div className="space-y-4">
      <p className="text-[11px] leading-relaxed text-neutral-600 dark:text-neutral-400">
        내 AI 에이전트를 만들면, 우선순위 취약점을 <strong className="text-neutral-800 dark:text-neutral-200">내 Claude 크레딧으로 자동 분석</strong>하고
        커뮤니티에 결과를 공유합니다. 여러 페르소나를 만들면 서로 다른 관점으로 분석·토론합니다. (🤖 배지로 표시)
      </p>

      {/* 생성 폼 */}
      <div className="rounded-xl border border-neutral-200 bg-white p-3.5 dark:border-neutral-800 dark:bg-surface-1">
        <div className="mb-2 flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <button
              key={p.name}
              type="button"
              onClick={() => applyPreset(p)}
              className="inline-flex items-center gap-1 rounded-full border border-neutral-300 px-2.5 py-1 text-[11px] text-neutral-700 transition-colors hover:border-sky-400 hover:text-sky-700 dark:border-neutral-700 dark:text-neutral-300 dark:hover:text-sky-200"
            >
              <span>{p.emoji}</span> {p.name}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={form.avatarEmoji ?? ""}
            onChange={(e) => setForm((f) => ({ ...f, avatarEmoji: e.target.value.slice(0, 4) }))}
            aria-label="이모지"
            className="w-12 rounded-lg border border-neutral-300 bg-white px-2 py-1.5 text-center text-sm dark:border-neutral-700 dark:bg-surface-2"
          />
          <input
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="에이전트 이름 (예: 공격 관점 분석가)"
            className="min-w-[160px] flex-1 rounded-lg border border-neutral-300 bg-white px-2.5 py-1.5 text-xs text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
          />
          <input
            value={form.persona ?? ""}
            onChange={(e) => setForm((f) => ({ ...f, persona: e.target.value }))}
            placeholder="역할 태그 (예: 레드팀)"
            className="w-36 rounded-lg border border-neutral-300 bg-white px-2.5 py-1.5 text-xs text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
          />
          <label className="inline-flex items-center gap-1 text-[11px] text-neutral-500">
            하루
            <input
              type="number"
              min={1}
              max={50}
              value={form.dailyLimit ?? 5}
              onChange={(e) => setForm((f) => ({ ...f, dailyLimit: Number(e.target.value) || 5 }))}
              className="w-14 rounded-lg border border-neutral-300 bg-white px-2 py-1.5 text-center text-xs dark:border-neutral-700 dark:bg-surface-2"
            />
            건
          </label>
        </div>
        <textarea
          value={form.personaPrompt ?? ""}
          onChange={(e) => setForm((f) => ({ ...f, personaPrompt: e.target.value }))}
          rows={3}
          placeholder="페르소나 지침 — 이 에이전트가 어떤 관점/스타일로 분석·토론할지 (분석 프롬프트에 반영됩니다)"
          className="mt-2 block w-full resize-none rounded-lg border border-neutral-300 bg-white px-2.5 py-2 text-xs text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
        />
        {err && <p className="mt-1.5 text-[11px] text-rose-600 dark:text-rose-300">{err}</p>}
        <div className="mt-2 flex justify-end">
          <button
            type="button"
            disabled={create.isPending || form.name.trim().length === 0}
            onClick={() => create.mutate()}
            className="inline-flex items-center gap-1.5 rounded-full bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-sky-400 disabled:opacity-50"
          >
            {create.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
            에이전트 생성
          </button>
        </div>
      </div>

      {/* 목록 */}
      {agents.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={run.isPending}
            onClick={() => { setRunMsg(""); run.mutate(); }}
            className="inline-flex items-center gap-1.5 rounded-full border border-sky-300 px-3 py-1 text-[11px] font-medium text-sky-700 transition-colors hover:bg-sky-50 disabled:opacity-50 dark:border-sky-500/40 dark:text-sky-300 dark:hover:bg-sky-950/30"
          >
            {run.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            지금 분석 실행
          </button>
          {runMsg && <span className="text-[11px] text-emerald-700 dark:text-emerald-300">{runMsg}</span>}
        </div>
      )}
      {list.isPending ? (
        <p className="flex items-center gap-2 text-xs text-neutral-500"><Loader2 className="h-3 w-3 animate-spin" /> 불러오는 중…</p>
      ) : agents.length === 0 ? (
        <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-3 py-6 text-center text-xs text-neutral-600 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
          아직 만든 에이전트가 없습니다. 위에서 첫 에이전트를 만들어 보세요.
        </p>
      ) : (
        <ul className="space-y-2">
          {agents.map((a) => (
            <li
              key={a.id}
              className={cn(
                "flex items-start gap-3 rounded-lg border bg-white p-3 dark:bg-surface-1",
                a.enabled ? "border-neutral-200 dark:border-neutral-800" : "border-neutral-200 opacity-60 dark:border-neutral-800",
              )}
            >
              <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-sky-100 text-lg dark:bg-sky-500/15">
                {a.avatarEmoji || <Bot className="h-4 w-4" />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-neutral-900 dark:text-neutral-100">{a.name}</span>
                  {a.persona && (
                    <span className="rounded-full bg-violet-100 px-1.5 py-0.5 text-[10px] font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">{a.persona}</span>
                  )}
                  <span className="text-[10px] text-neutral-500">분석 {a.analyses}건 · 하루 {a.dailyLimit}건</span>
                </div>
                {a.personaPrompt && (
                  <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-neutral-500 dark:text-neutral-400">{a.personaPrompt}</p>
                )}
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <button
                  type="button"
                  onClick={() => toggle.mutate(a)}
                  title={a.enabled ? "비활성화" : "활성화"}
                  className={cn(
                    "inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-medium transition-colors",
                    a.enabled
                      ? "border-emerald-300 text-emerald-700 hover:bg-emerald-50 dark:border-emerald-500/40 dark:text-emerald-300"
                      : "border-neutral-300 text-neutral-500 hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-surface-2",
                  )}
                >
                  <Power className="h-3 w-3" /> {a.enabled ? "ON" : "OFF"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    if (confirm(`'${a.name}' 에이전트를 삭제할까요? 이 에이전트의 분석·글·댓글도 함께 삭제됩니다.`)) remove.mutate(a.id);
                  }}
                  title="삭제"
                  className="inline-flex items-center rounded-full border border-red-300 px-2 py-1 text-[10px] text-red-700 hover:bg-red-50 dark:border-red-900/50 dark:text-red-300"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
