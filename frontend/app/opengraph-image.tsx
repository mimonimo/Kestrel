import { ImageResponse } from "next/og";

// 링크 공유(카카오톡·슬랙·디스코드·페북·트위터) 시 보이는 썸네일 카드.
// Next.js 파일 컨벤션 — 자동으로 og:image 메타에 연결된다. (PR 10-FF)
// 한글 폰트 임베드는 생략(tofu 방지) → 이미지 텍스트는 영문, 카드 제목/설명
// 메타는 한글(클라이언트 폰트로 렌더).
// runtime 은 nodejs(기본) — 자체 호스팅 standalone 빌드에선 edge 런타임의
// ImageResponse(satori/resvg WASM)가 "failed to pipe response" 로 502 가 난다.
export const alt = "Kestrel — Real-time CVE & Zero-day Monitoring";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          padding: "80px",
          background:
            "radial-gradient(1200px 600px at 80% -10%, #1e3a8a 0%, #0b1220 45%, #060a14 100%)",
          color: "#e5e7eb",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "28px" }}>
          {/* Kestrel bird (lucide Bird, brand blue) */}
          <svg
            width="120"
            height="120"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#3b82f6"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M16 7h.01" />
            <path d="M3.4 18H12a8 8 0 0 0 8-8V7a4 4 0 0 0-7.28-2.3L2 20" />
            <path d="m20 7 2 .5-2 .5" />
            <path d="M10 18v3" />
            <path d="M14 17.75V21" />
            <path d="M7 18a6 6 0 0 0 3.84-10.61" />
          </svg>
          <div style={{ fontSize: "104px", fontWeight: 800, color: "#ffffff", letterSpacing: "-2px" }}>
            Kestrel
          </div>
        </div>

        <div style={{ marginTop: "36px", fontSize: "44px", fontWeight: 600, color: "#cbd5e1" }}>
          Real-time CVE &amp; Zero-day Monitoring
        </div>
        <div style={{ marginTop: "18px", fontSize: "30px", color: "#7dd3fc" }}>
          NVD · Exploit-DB · GitHub Advisory · MITRE
        </div>

        <div
          style={{
            marginTop: "auto",
            fontSize: "28px",
            color: "#64748b",
            display: "flex",
          }}
        >
          www.kestrel.forum
        </div>
      </div>
    ),
    { ...size },
  );
}
