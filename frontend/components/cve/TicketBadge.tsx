"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { STATUS_META } from "./TicketControl";
import { cn } from "@/lib/utils";

export function TicketBadge({ cveId }: { cveId: string }) {
  const { data } = useQuery({
    queryKey: ["tickets"],
    queryFn: () => api.listTickets(),
    staleTime: 10_000,
  });
  const ticket = data?.items.find((t) => t.cveId === cveId);
  if (!ticket) return null;
  const meta = STATUS_META[ticket.status];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium",
        meta.cls,
      )}
      title={`대응 상태: ${meta.label}`}
    >
      {meta.label}
    </span>
  );
}
