"use client";

import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

// Resolve the WebSocket URL for the PTY endpoint. We mirror the
// `NEXT_PUBLIC_API_BASE_URL` host (default localhost:8000) but swap
// scheme to ws/wss. Production deployments that proxy /api/v1 through
// nginx need to route /api/v1/sandbox/sessions/{id}/pty too — that's a
// vanilla WebSocket upgrade, no special headers required.
function ptyWsUrl(sessionId: string): string {
  const base =
    process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";
  const wsBase = base.replace(/^http/, "ws");
  return `${wsBase}/sandbox/sessions/${encodeURIComponent(sessionId)}/pty`;
}

export function PtyTerminal({ sessionId }: { sessionId: string }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const [status, setStatus] = useState<"connecting" | "open" | "closed" | "error">(
    "connecting",
  );
  const [closeReason, setCloseReason] = useState<string | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      fontFamily:
        "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
      fontSize: 12,
      theme: {
        background: "#0a0a0a",
        foreground: "#e5e5e5",
        cursor: "#84cc16",
      },
      cursorBlink: true,
      scrollback: 5000,
      convertEol: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const ws = new WebSocket(ptyWsUrl(sessionId));
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    const sendResize = () => {
      if (ws.readyState !== WebSocket.OPEN) return;
      try {
        fit.fit();
      } catch {
        // ignore — happens when the panel is hidden
      }
      ws.send(
        JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }),
      );
    };

    ws.onopen = () => {
      setStatus("open");
      sendResize();
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "exit") {
            setCloseReason(msg.reason ?? "session ended");
          }
        } catch {
          // unknown text frame — write through
          term.write(ev.data);
        }
        return;
      }
      // binary frame — raw PTY output
      term.write(new Uint8Array(ev.data));
    };
    ws.onerror = () => {
      setStatus("error");
    };
    ws.onclose = () => {
      setStatus("closed");
    };

    const dataDisposable = term.onData((d: string) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(d);
    });

    // Resize on window changes + when the wrapping panel layout shifts.
    const ro = new ResizeObserver(() => sendResize());
    ro.observe(containerRef.current);
    window.addEventListener("resize", sendResize);

    return () => {
      window.removeEventListener("resize", sendResize);
      ro.disconnect();
      dataDisposable.dispose();
      try {
        ws.close();
      } catch {
        /* ignore */
      }
      term.dispose();
      termRef.current = null;
      wsRef.current = null;
      fitRef.current = null;
    };
  }, [sessionId]);

  const statusLabel = (() => {
    if (closeReason) return `종료: ${closeReason}`;
    if (status === "connecting") return "연결 중…";
    if (status === "open") return "연결됨";
    if (status === "closed") return "닫힘";
    return "오류";
  })();
  const statusColor =
    status === "open"
      ? "text-emerald-300"
      : status === "error" || closeReason
        ? "text-rose-300"
        : "text-neutral-400";

  return (
    <div className="mt-3 overflow-hidden rounded border border-neutral-800 bg-black/60">
      <div className="flex items-center justify-between gap-2 border-b border-neutral-800 px-3 py-1.5 text-xs text-neutral-400">
        <span>인터랙티브 셸 (xterm + WebSocket PTY)</span>
        <span className={statusColor}>{statusLabel}</span>
      </div>
      <div ref={containerRef} className="h-72 w-full" />
    </div>
  );
}
