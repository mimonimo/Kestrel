import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
  experimental: {
    typedRoutes: true,
  },
  // OG 이미지(app/opengraph-image.tsx) 의 ImageResponse 는 @vercel/og 의
  // resvg/yoga WASM + noto-sans 폰트를 런타임에 fs 로 읽는데, standalone 빌드의
  // 파일 트레이서가 이 바이너리 asset 을 못 따라가 누락 → "failed to pipe response"
  // 502. 해당 라우트에 @vercel/og 전체를 강제 포함시킨다. (PR 10-FI)
  outputFileTracingIncludes: {
    "/opengraph-image": ["./node_modules/next/dist/compiled/@vercel/og/**/*"],
  },
};

export default nextConfig;
