// CVSS 벡터 문자열을 사람이 읽는 라벨로 디코드 — 상세 페이지에서
// "AV:N/AC:L/..." 대신 "공격 벡터: 네트워크" 식으로 보여주기 위함.
// CVSS 3.x / 4.0 / 2.0 의 base 메트릭만 다룬다(분석에 가장 중요한 부분).

interface Dim {
  label: string;
  values: Record<string, string>;
}

// 공통 영향도(High/Low/None)
const IMPACT: Record<string, string> = { H: "높음", L: "낮음", N: "없음", P: "부분", C: "완전" };

const V3: Record<string, Dim> = {
  AV: { label: "공격 벡터", values: { N: "네트워크", A: "인접", L: "로컬", P: "물리" } },
  AC: { label: "공격 복잡도", values: { L: "낮음", H: "높음" } },
  PR: { label: "필요 권한", values: { N: "불필요", L: "낮음", H: "높음" } },
  UI: { label: "사용자 상호작용", values: { N: "불필요", R: "필요" } },
  S: { label: "범위", values: { U: "불변", C: "변경" } },
  C: { label: "기밀성 영향", values: IMPACT },
  I: { label: "무결성 영향", values: IMPACT },
  A: { label: "가용성 영향", values: IMPACT },
};

const V4: Record<string, Dim> = {
  AV: V3.AV,
  AC: V3.AC,
  AT: { label: "공격 요건", values: { N: "없음", P: "있음" } },
  PR: V3.PR,
  UI: { label: "사용자 상호작용", values: { N: "불필요", P: "수동적", A: "능동적" } },
  VC: { label: "기밀성 영향", values: IMPACT },
  VI: { label: "무결성 영향", values: IMPACT },
  VA: { label: "가용성 영향", values: IMPACT },
  SC: { label: "후속 기밀성", values: IMPACT },
  SI: { label: "후속 무결성", values: IMPACT },
  SA: { label: "후속 가용성", values: IMPACT },
};

const V2: Record<string, Dim> = {
  AV: { label: "공격 벡터", values: { N: "네트워크", A: "인접", L: "로컬" } },
  AC: { label: "공격 복잡도", values: { L: "낮음", M: "중간", H: "높음" } },
  Au: { label: "인증", values: { N: "불필요", S: "1회", M: "다중" } },
  C: { label: "기밀성 영향", values: IMPACT },
  I: { label: "무결성 영향", values: IMPACT },
  A: { label: "가용성 영향", values: IMPACT },
};

export interface DecodedMetric {
  key: string;
  label: string;
  value: string;
  group: "exploit" | "impact";
  tone: "high" | "med" | "low";
  /** 이 값이 무엇을 뜻하고 왜 위험/안전한지 — 호버 툴팁용 평문 설명. */
  hint: string;
}

// 영향 메트릭 키(영향 그룹). 나머지는 악용 경로 그룹.
const IMPACT_KEYS = new Set(["C", "I", "A", "VC", "VI", "VA", "SC", "SI", "SA"]);

// 악용 경로 메트릭의 값별 평문 설명(코드 기준). 사용자가 "왜 위험/안전한지"
// 한눈에 알도록 — 메트릭 의미 + 해당 값의 함의를 함께 적는다.
const EXPLOIT_HINT: Record<string, Record<string, string>> = {
  AV: {
    N: "공격 벡터: 인터넷 등 네트워크를 통해 원격에서 공격 가능 — 접근 장벽이 없어 가장 위험",
    A: "공격 벡터: 같은 네트워크(인접 망)에 있어야 공격 가능",
    L: "공격 벡터: 대상에 로컬 접근(셸/계정)이 있어야 공격 가능 — 위험 낮음",
    P: "공격 벡터: 기기에 물리적으로 접근해야 공격 가능 — 위험 매우 낮음",
  },
  AC: {
    L: "공격 복잡도: 특별한 조건 없이 반복적으로 쉽게 악용 가능 — 위험",
    M: "공격 복잡도: 악용에 일정 조건이 필요(중간)",
    H: "공격 복잡도: 경쟁 조건·특수 설정 등 까다로운 선행조건 필요 — 성공률 낮음",
  },
  AT: {
    N: "공격 요건: 별도의 선행 조건 없이 악용 가능",
    P: "공격 요건: 특정 사전 조건이 갖춰져야 악용 가능",
  },
  PR: {
    N: "필요 권한: 아무 권한 없이(비인증) 공격 가능 — 위험",
    L: "필요 권한: 일반 사용자 수준의 권한만 있으면 공격 가능",
    H: "필요 권한: 관리자급 높은 권한이 있어야 공격 가능 — 위험 낮음",
  },
  UI: {
    N: "사용자 상호작용: 피해자의 어떤 행동도 없이 자동 악용 — 위험",
    R: "사용자 상호작용: 피해자가 링크 클릭·파일 열기 등 행동을 해야 악용",
    P: "사용자 상호작용: 피해자의 수동적 상호작용이 필요",
    A: "사용자 상호작용: 피해자의 능동적 상호작용이 필요",
  },
  Au: {
    N: "인증: 인증 절차 없이 공격 가능 — 위험",
    S: "인증: 1회 인증이 필요",
    M: "인증: 여러 단계 인증이 필요 — 위험 낮음",
  },
  S: {
    U: "범위: 영향이 취약한 컴포넌트 내부로 한정(범위 불변)",
    C: "범위: 취약 컴포넌트를 넘어 다른 시스템으로 피해가 확대(범위 변경) — 위험",
  },
};

// 영향 메트릭(기밀성/무결성/가용성 등) 설명 — 차원 이름 + 손상 정도.
function impactHint(label: string, code: string): string {
  const noun = label.replace(/\s*영향$/, ""); // "기밀성 영향" → "기밀성"
  if (code === "H" || code === "C")
    return `${noun}: 완전한 손상 가능(전체 유출·변조·중단 등) — 위험`;
  if (code === "L" || code === "P") return `${noun}: 제한적·부분적 손상`;
  return `${noun}: 영향 없음`;
}

// 각 (라벨 한글) 값의 위험 강도 — 칩 색상용.
function toneOf(group: "exploit" | "impact", value: string): "high" | "med" | "low" {
  if (group === "impact") {
    if (value === "높음" || value === "완전") return "high";
    if (value === "낮음" || value === "부분") return "med";
    return "low"; // 없음
  }
  // 악용 경로: 공격이 쉬울수록 high
  if (["네트워크", "불필요", "낮음", "있음", "능동적"].includes(value)) return "high";
  if (["인접", "수동적", "중간", "변경", "1회"].includes(value)) return "med";
  return "low";
}

/** "CVSS:3.1/AV:N/AC:L/..." → 라벨 디코드된 base 메트릭 목록. 모르면 빈 배열. */
export function decodeCvssVector(vector?: string | null): DecodedMetric[] {
  if (!vector) return [];
  const upper = vector.trim();
  const is4 = /CVSS:4/.test(upper);
  const is3 = /CVSS:3/.test(upper);
  const dims = is4 ? V4 : is3 ? V3 : V2;
  const out: DecodedMetric[] = [];
  for (const part of upper.split("/")) {
    const [k, v] = part.split(":");
    if (!k || !v || k.startsWith("CVSS")) continue;
    const dim = dims[k];
    if (!dim) continue; // 환경/시간 메트릭 등은 생략(base 만)
    const label = dim.values[v];
    if (!label) continue;
    const group: "exploit" | "impact" = IMPACT_KEYS.has(k) ? "impact" : "exploit";
    const hint = group === "impact" ? impactHint(dim.label, v) : EXPLOIT_HINT[k]?.[v] ?? dim.label;
    out.push({ key: k, label: dim.label, value: label, group, tone: toneOf(group, label), hint });
  }
  return out;
}
