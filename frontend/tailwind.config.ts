import type { Config } from "tailwindcss";

export default {
  darkMode: "class",
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        severity: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#22c55e",
        },
        // Dark surface ramp tuned softer than pure black so the UI feels
        // more like Linear/Vercel and less like a terminal. Surface-0 sits
        // around HSL ~220° 12% 11% (slight cool tint); each step up adds
        // ~3% lightness so cards and pop-overs read distinct without
        // turning grey-blue. See feedback "다크모드 너무 다크 말고 조금 덜 다크로".
        surface: {
          0: "#15171c",  // page bg
          1: "#1c1e24",  // card / panel
          2: "#23262d",  // raised input / chip bg
          3: "#2b2f37",  // hover / active raise
        },
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
} satisfies Config;
