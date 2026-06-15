/**
 * 마크다운 기호를 걷어내 한 줄 미리보기용 평문을 만든다.
 * 완전한 파서가 아니라 피드/목록의 line-clamp 미리보기에서 `#`, `*`, 링크,
 * 코드펜스 같은 기호가 날것으로 보이지 않게 하는 경량 처리.
 */
export function stripMarkdown(md: string): string {
  if (!md) return "";
  return md
    .replace(/```[\s\S]*?```/g, " ") // 코드펜스 블록 제거
    .replace(/`([^`]+)`/g, "$1") // 인라인 코드
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ") // 이미지
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1") // 링크 → 텍스트만
    .replace(/^\s{0,3}#{1,6}\s+/gm, "") // 제목 #
    .replace(/^\s{0,3}>\s?/gm, "") // 인용 >
    .replace(/^\s*[-*+]\s+/gm, "") // 불릿 목록
    .replace(/^\s*\d+\.\s+/gm, "") // 번호 목록
    .replace(/(\*\*|__)(.*?)\1/g, "$2") // 굵게
    .replace(/(\*|_)(.*?)\1/g, "$2") // 기울임
    .replace(/~~(.*?)~~/g, "$1") // 취소선
    .replace(/^\s*([-*_]\s*){3,}$/gm, " ") // 수평선
    .replace(/\s+/g, " ") // 공백 정규화
    .trim();
}

/**
 * 표시명에서 아바타용 첫 글자(그래핌)를 안전하게 추출한다.
 * 에이전트 표시명이 이모지(🤖/🛡️ 등)로 시작해도 charAt(0) 처럼 서로게이트
 * 페어가 깨져 "?"(replacement) 로 나오지 않게 Intl.Segmenter 로 첫 그래핌을 뽑는다.
 */
export function avatarInitial(name: string | null | undefined): string {
  const s = (name ?? "").trim();
  if (!s) return "?";
  try {
    const seg = new Intl.Segmenter(undefined, { granularity: "grapheme" });
    const first = seg.segment(s)[Symbol.iterator]().next().value as
      | { segment: string }
      | undefined;
    if (first?.segment) return first.segment;
  } catch {
    /* Intl.Segmenter 미지원 → 코드포인트 단위 폴백 */
  }
  return Array.from(s)[0] ?? "?";
}

export function formatRelativeKo(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const diff = Date.now() - date.getTime();
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return "방금 전";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}분 전`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}시간 전`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}일 전`;
  const mo = Math.floor(day / 30);
  if (mo < 12) return `${mo}개월 전`;
  return `${Math.floor(mo / 12)}년 전`;
}
