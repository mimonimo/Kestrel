import { useEffect } from "react";

// 모달/팝업이 열려 있는 동안 뒤 배경 스크롤을 잠근다.
// 스크롤바 사라짐에 따른 레이아웃 점프를 막기 위해 padding 으로 보정.
export function useBodyScrollLock(active: boolean) {
  useEffect(() => {
    if (!active || typeof document === "undefined") return;
    const body = document.body;
    const prevOverflow = body.style.overflow;
    const prevPaddingRight = body.style.paddingRight;
    const scrollbar = window.innerWidth - document.documentElement.clientWidth;
    body.style.overflow = "hidden";
    if (scrollbar > 0) body.style.paddingRight = `${scrollbar}px`;
    return () => {
      body.style.overflow = prevOverflow;
      body.style.paddingRight = prevPaddingRight;
    };
  }, [active]);
}
