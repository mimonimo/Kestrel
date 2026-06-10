import type { MetadataRoute } from "next";

const BASE = "https://www.kestrel.forum";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      // 인증·개인 영역은 색인 불필요.
      disallow: [
        "/settings",
        "/login",
        "/signup",
        "/verify-email",
        "/forgot-password",
        "/reset-password",
      ],
    },
    sitemap: `${BASE}/sitemap.xml`,
    host: BASE,
  };
}
