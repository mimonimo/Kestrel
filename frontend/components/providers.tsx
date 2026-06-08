"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { ThemeProvider } from "@/lib/theme";
import { AuthProvider } from "@/lib/auth-context";
import { IdleLogoutGuard } from "@/components/system/IdleLogoutGuard";

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 60_000,
            gcTime: 5 * 60_000,
            refetchOnWindowFocus: false,
            retry: 1,
          },
        },
      }),
  );
  return (
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <AuthProvider>
          <IdleLogoutGuard />
          {children}
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
