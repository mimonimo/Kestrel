"use client";

// 루트 레이아웃 자체가 깨졌을 때를 위한 최후의 폴백. 자체 <html>/<body> 필요.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="ko">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0a0a0b",
          color: "#e5e7eb",
          fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
        }}
      >
        <div style={{ textAlign: "center", padding: "0 24px", maxWidth: 420 }}>
          <h1 style={{ fontSize: 18, fontWeight: 600 }}>문제가 발생했습니다</h1>
          <p style={{ fontSize: 14, color: "#9ca3af", marginTop: 8 }}>
            예기치 못한 오류가 발생했습니다. 다시 시도해 주세요.
          </p>
          <button
            type="button"
            onClick={() => reset()}
            style={{
              marginTop: 16,
              background: "#0ea5e9",
              color: "#fff",
              border: 0,
              borderRadius: 9999,
              padding: "10px 20px",
              fontSize: 14,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            다시 시도
          </button>
        </div>
      </body>
    </html>
  );
}
