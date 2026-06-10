import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Kestrel — 취약점 인텔리전스",
    short_name: "Kestrel",
    description: "CVSS 이론 · EPSS 예측 · KEV 실측 · AI 심층 분석",
    start_url: "/",
    display: "standalone",
    background_color: "#0a0a0b",
    theme_color: "#0a0a0b",
    icons: [
      { src: "/icon.svg", sizes: "any", type: "image/svg+xml" },
    ],
  };
}
