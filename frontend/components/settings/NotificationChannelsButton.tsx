"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { Bell, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { NotificationChannelsPanel } from "./NotificationChannelsPanel";

// 알림 채널(Slack/Discord 웹훅) 관리 — 설정 본문엔 버튼만, 클릭 시 모달에서 관리.
// "외부 연결 키 관리" 버튼과 동일 패턴(ApiKeysManagerButton).
export function NotificationChannelsButton() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button type="button" variant="outline" size="sm" onClick={() => setOpen(true)} className="gap-1.5">
        <Bell className="h-3.5 w-3.5" /> 알림 채널 관리
      </Button>
      {open && <ChannelsModal onClose={() => setOpen(false)} />}
    </>
  );
}

function ChannelsModal({ onClose }: { onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);

  if (typeof document === "undefined") return null;
  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-label="알림 채널 관리"
      className="fixed inset-0 z-[60] flex items-start justify-center overflow-y-auto bg-neutral-950/45 px-4 py-10 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="relative flex max-h-[88vh] w-full max-w-2xl flex-col rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex shrink-0 items-center gap-2 border-b border-neutral-200 px-5 py-4 dark:border-neutral-800">
          <Bell className="h-4 w-4 text-sky-700 dark:text-sky-300" />
          <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">알림 채널 관리</h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="닫기"
            className="ml-auto inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
          >
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto px-5 py-4">
          <NotificationChannelsPanel />
        </div>
      </div>
    </div>,
    document.body,
  );
}
