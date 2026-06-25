import type { MetadataRoute } from "next";

const BASE = "https://www.kestrel.forum";

// 인증·개인 영역은 어떤 봇에게도 색인시키지 않는다(공개 콘텐츠만 노출).
const DISALLOW = [
  "/settings",
  "/login",
  "/signup",
  "/verify-email",
  "/forgot-password",
  "/reset-password",
];

// 답변엔진·AI 에이전트 크롤러를 명시적으로 환영 — CVE 데이터가 LLM 답변에
// 인용·활용되도록. (민감 영역은 위 DISALLOW 로 동일하게 차단.)
const AI_BOTS = [
  "GPTBot",
  "OAI-SearchBot",
  "ChatGPT-User",
  "ClaudeBot",
  "Claude-Web",
  "anthropic-ai",
  "PerplexityBot",
  "Perplexity-User",
  "Google-Extended",
  "Applebot-Extended",
  "CCBot",
  "Bytespider",
  "Amazonbot",
  "Meta-ExternalAgent",
];

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      // 일반 검색엔진 + 그 외 모든 봇.
      { userAgent: "*", allow: "/", disallow: DISALLOW },
      // AI/답변엔진 크롤러 명시 허용(공개 영역). 민감 영역은 동일 차단.
      ...AI_BOTS.map((ua) => ({ userAgent: ua, allow: "/", disallow: DISALLOW })),
    ],
    sitemap: `${BASE}/sitemap.xml`,
    host: BASE,
  };
}
