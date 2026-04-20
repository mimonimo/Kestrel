"use client";

import { useCallback, useEffect, useState } from "react";

const PREFIX = "kestrel:setting:";

export type SettingKey = "nvdApiKey" | "githubToken";

export const SETTING_META: Record<
  SettingKey,
  { label: string; placeholder: string; help: string; docsUrl: string }
> = {
  nvdApiKey: {
    label: "NVD API Key",
    placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    help: "NVD 2.0 API의 레이트 리밋을 30초당 5회 → 50회로 끌어올립니다.",
    docsUrl: "https://nvd.nist.gov/developers/request-an-api-key",
  },
  githubToken: {
    label: "GitHub Personal Access Token",
    placeholder: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    help: "GitHub Advisory API 호출 시 인증에 사용됩니다. repo scope 불필요.",
    docsUrl: "https://github.com/settings/tokens",
  },
};

function read(key: SettingKey): string {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(PREFIX + key) ?? "";
}

function write(key: SettingKey, value: string) {
  if (!value) {
    window.localStorage.removeItem(PREFIX + key);
  } else {
    window.localStorage.setItem(PREFIX + key, value);
  }
}

export function useUserSetting(key: SettingKey) {
  const [value, setValue] = useState<string>("");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    setValue(read(key));
    setReady(true);
  }, [key]);

  const save = useCallback(
    (next: string) => {
      write(key, next);
      setValue(next);
    },
    [key],
  );

  const clear = useCallback(() => {
    write(key, "");
    setValue("");
  }, [key]);

  return { value, ready, save, clear };
}

export function maskSecret(secret: string): string {
  if (!secret) return "";
  if (secret.length <= 8) return "•".repeat(secret.length);
  return secret.slice(0, 4) + "•".repeat(Math.max(4, secret.length - 8)) + secret.slice(-4);
}
