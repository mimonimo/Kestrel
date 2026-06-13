import { useEffect } from "react";

// 모달/팝업이 열린 동안 뒤 배경 스크롤을 잠근다.
// 여러 모달이 겹치거나 정리 순서가 엉켜도 잠금이 남지 않도록 *전역 잠금 카운터*
// 를 쓴다. 카운터가 0→1 일 때만 원래 스타일을 저장하고 잠그며, 1→0 으로
// 모두 해제됐을 때만 원래대로 복원한다(스크롤 영구 잠김 회귀 방지).
let lockCount = 0;
let savedOverflow = "";
let savedPaddingRight = "";

export function useBodyScrollLock(active: boolean) {
  useEffect(() => {
    if (!active || typeof document === "undefined") return;
    const body = document.body;
    if (lockCount === 0) {
      savedOverflow = body.style.overflow;
      savedPaddingRight = body.style.paddingRight;
      const scrollbar = window.innerWidth - document.documentElement.clientWidth;
      body.style.overflow = "hidden";
      if (scrollbar > 0) body.style.paddingRight = `${scrollbar}px`;
    }
    lockCount += 1;
    return () => {
      lockCount = Math.max(0, lockCount - 1);
      if (lockCount === 0) {
        body.style.overflow = savedOverflow;
        body.style.paddingRight = savedPaddingRight;
      }
    };
  }, [active]);
}
