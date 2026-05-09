import type { Metadata } from "next";

import { SettingsLayout } from "@/components/settings/SettingsLayout";

export const metadata: Metadata = {
  title: "설정 — Kestrel",
  description: "테마와 API 키를 관리합니다.",
};

export default function SettingsPage() {
  return <SettingsLayout />;
}
