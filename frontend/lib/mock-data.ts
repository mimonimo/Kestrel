import type { Vulnerability } from "./types";

export const MOCK_VULNERABILITIES: Vulnerability[] = [
  {
    id: "1",
    cveId: "CVE-2026-31415",
    title: "OpenSSL 3.5 — Heap buffer overflow in TLS 1.3 handshake",
    description:
      "OpenSSL 3.5.0 이전 버전의 TLS 1.3 핸드셰이크 처리에서 힙 버퍼 오버플로가 발생하여 원격 공격자가 임의 코드를 실행할 수 있습니다. 특수하게 조작된 ClientHello 메시지를 통해 트리거됩니다.",
    summary:
      "OpenSSL 3.5 이전의 TLS 1.3 핸드셰이크에서 힙 버퍼 오버플로. 원격 코드 실행 가능. 즉시 패치 권장.",
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    severity: "critical",
    publishedAt: "2026-04-17T09:15:00Z",
    modifiedAt: "2026-04-18T12:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-31415",
    types: ["RCE"],
    affectedProducts: [
      { vendor: "OpenSSL", product: "OpenSSL", osFamily: "linux", versionRange: "< 3.5.0" },
      { vendor: "OpenSSL", product: "OpenSSL", osFamily: "windows", versionRange: "< 3.5.0" },
      { vendor: "OpenSSL", product: "OpenSSL", osFamily: "macos", versionRange: "< 3.5.0" },
    ],
    references: [
      { url: "https://www.openssl.org/news/secadv/20260417.txt", type: "advisory" },
      { url: "https://github.com/openssl/openssl/commit/deadbeef", type: "patch" },
    ],
  },
  {
    id: "2",
    cveId: "CVE-2026-20482",
    title: "Microsoft Windows Kernel — Elevation of Privilege via NTFS race",
    description:
      "Windows 11 24H2 및 Windows Server 2025의 NTFS 드라이버에서 TOCTOU 레이스 컨디션이 존재하여 로컬 공격자가 SYSTEM 권한을 획득할 수 있습니다.",
    summary: "Windows 11/Server 2025 NTFS TOCTOU. 로컬 권한 상승 (SYSTEM). 2026년 4월 패치데이 반영.",
    cvssScore: 7.8,
    cvssVector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    severity: "high",
    publishedAt: "2026-04-15T18:00:00Z",
    modifiedAt: "2026-04-15T18:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-20482",
    types: ["Auth"],
    affectedProducts: [
      { vendor: "Microsoft", product: "Windows 11", osFamily: "windows", versionRange: "24H2" },
      { vendor: "Microsoft", product: "Windows Server", osFamily: "windows", versionRange: "2025" },
    ],
    references: [
      { url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20482", type: "advisory" },
    ],
  },
  {
    id: "3",
    cveId: "CVE-2026-0081",
    title: "Next.js Middleware — Authorization bypass via crafted header",
    description:
      "Next.js 15.0.3 이전 버전의 미들웨어가 특정 헤더 조합을 처리할 때 인증 검사를 건너뛰어 보호된 라우트에 인증 없이 접근할 수 있는 취약점입니다.",
    summary: "Next.js 15.0.3 미만 미들웨어 인가 우회. 보호 라우트 무인증 접근 가능.",
    cvssScore: 8.2,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    severity: "high",
    publishedAt: "2026-04-10T10:00:00Z",
    modifiedAt: "2026-04-12T08:30:00Z",
    source: "github_advisory",
    sourceUrl: "https://github.com/vercel/next.js/security/advisories/GHSA-xxxx-xxxx-xxxx",
    types: ["Auth"],
    affectedProducts: [
      { vendor: "Vercel", product: "Next.js", osFamily: "other", versionRange: "< 15.0.3" },
    ],
    references: [
      { url: "https://github.com/vercel/next.js/security/advisories/GHSA-xxxx-xxxx-xxxx", type: "advisory" },
      { url: "https://github.com/vercel/next.js/pull/99999", type: "patch" },
    ],
  },
  {
    id: "4",
    cveId: "CVE-2026-11007",
    title: "WordPress Plugin CommentPro — Stored XSS in comment field",
    description:
      "인기 WordPress 댓글 플러그인에서 입력 검증 미흡으로 저장형 XSS가 발생합니다. 로그인한 관리자가 댓글을 열람하면 공격자 스크립트가 실행됩니다.",
    summary: "WordPress 플러그인 저장형 XSS. 관리자 계정 탈취 경로 존재.",
    cvssScore: 6.1,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    severity: "medium",
    publishedAt: "2026-04-08T00:00:00Z",
    modifiedAt: "2026-04-08T00:00:00Z",
    source: "exploit_db",
    sourceUrl: "https://www.exploit-db.com/exploits/52001",
    types: ["XSS"],
    affectedProducts: [
      { vendor: "Acme", product: "CommentPro", osFamily: "other", versionRange: "< 4.2.1" },
    ],
    references: [{ url: "https://www.exploit-db.com/exploits/52001", type: "exploit" }],
  },
  {
    id: "5",
    cveId: "CVE-2026-8822",
    title: "Apache Tomcat — SQL injection in management console",
    description:
      "Apache Tomcat 11.0.x 관리 콘솔의 사용자 조회 엔드포인트에서 파라미터 바인딩 누락으로 SQL 인젝션이 발생합니다.",
    summary: "Apache Tomcat 11.0.x 관리 콘솔 SQL 인젝션. 외부 노출 시 즉시 차단 권장.",
    cvssScore: 8.8,
    severity: "high",
    publishedAt: "2026-04-05T14:00:00Z",
    modifiedAt: "2026-04-06T09:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-8822",
    types: ["SQLi"],
    affectedProducts: [
      { vendor: "Apache", product: "Tomcat", osFamily: "linux", versionRange: "11.0.0 - 11.0.5" },
    ],
    references: [{ url: "https://tomcat.apache.org/security-11.html", type: "advisory" }],
  },
  {
    id: "6",
    cveId: "CVE-2026-7711",
    title: "macOS 15 — Sandbox escape via XPC service",
    description:
      "macOS Sequoia 15 이전의 특정 시스템 XPC 서비스에서 권한 검증 결함으로 앱 샌드박스 탈출이 가능합니다.",
    summary: "macOS 15 미만 XPC 샌드박스 탈출. App Store 앱으로도 악용 가능성.",
    cvssScore: 7.5,
    severity: "high",
    publishedAt: "2026-03-28T00:00:00Z",
    modifiedAt: "2026-03-30T00:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-7711",
    types: ["Auth"],
    affectedProducts: [
      { vendor: "Apple", product: "macOS", osFamily: "macos", versionRange: "< 15.0" },
    ],
    references: [{ url: "https://support.apple.com/en-us/HT215000", type: "advisory" }],
  },
  {
    id: "7",
    cveId: "CVE-2026-4455",
    title: "Linux Kernel io_uring — Use-after-free in submission path",
    description:
      "Linux 커널 6.12 미만의 io_uring 서브시스템에서 Use-after-free 결함이 존재하여 비특권 사용자가 권한 상승을 수행할 수 있습니다.",
    summary: "Linux io_uring UAF. 비특권 사용자 → root 권한 상승. 여러 배포판 패치 배포 중.",
    cvssScore: 7.8,
    cvssVector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    severity: "high",
    publishedAt: "2026-03-20T00:00:00Z",
    modifiedAt: "2026-03-22T00:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-4455",
    types: ["Auth"],
    affectedProducts: [
      { vendor: "Linux", product: "Kernel", osFamily: "linux", versionRange: "< 6.12" },
    ],
    references: [
      { url: "https://kernel.org/security/CVE-2026-4455", type: "advisory" },
      { url: "https://lore.kernel.org/io-uring/patch-url", type: "patch" },
    ],
  },
  {
    id: "8",
    cveId: "CVE-2026-2301",
    title: "Chrome V8 — Type confusion leads to RCE (0-day exploited ITW)",
    description:
      "Google Chrome 128 이전 버전의 V8 엔진에서 Type Confusion 취약점이 야생에서 악용되고 있습니다. 악성 웹페이지 방문만으로 임의 코드 실행이 가능합니다.",
    summary: "Chrome V8 제로데이 (ITW 악용 중). 페이지 방문만으로 RCE. 브라우저 즉시 업데이트.",
    cvssScore: 9.6,
    severity: "critical",
    publishedAt: "2026-03-18T12:00:00Z",
    modifiedAt: "2026-03-19T00:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-2301",
    types: ["RCE"],
    affectedProducts: [
      { vendor: "Google", product: "Chrome", osFamily: "windows", versionRange: "< 128.0.6613.84" },
      { vendor: "Google", product: "Chrome", osFamily: "macos", versionRange: "< 128.0.6613.84" },
      { vendor: "Google", product: "Chrome", osFamily: "linux", versionRange: "< 128.0.6613.84" },
    ],
    references: [
      { url: "https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop.html", type: "advisory" },
    ],
  },
  {
    id: "9",
    cveId: "CVE-2026-13500",
    title: "Spring Framework — SpEL injection in data binding",
    description:
      "Spring Framework 6.3.x의 파라미터 바인딩 처리에서 SpEL 식이 평가되어 원격 코드 실행이 가능합니다. Spring Boot 3.5 기반 애플리케이션 다수 영향.",
    summary: "Spring Framework SpEL 인젝션. Spring Boot 3.5 기반 앱 RCE 가능.",
    cvssScore: 9.1,
    severity: "critical",
    publishedAt: "2026-03-12T00:00:00Z",
    modifiedAt: "2026-03-14T00:00:00Z",
    source: "github_advisory",
    sourceUrl: "https://github.com/spring-projects/spring-framework/security/advisories/GHSA-xxxx-2026-13500",
    types: ["RCE"],
    affectedProducts: [
      { vendor: "VMware", product: "Spring Framework", osFamily: "other", versionRange: "6.3.0 - 6.3.7" },
    ],
    references: [
      { url: "https://spring.io/security/cve-2026-13500", type: "advisory" },
    ],
  },
  {
    id: "10",
    cveId: "CVE-2026-9912",
    title: "Android MediaServer — Integer overflow in H.265 decoder",
    description:
      "Android 15의 MediaServer 프로세스 H.265 디코더에서 정수 오버플로가 발생, 조작된 영상 파일을 재생하면 미디어 권한으로 코드가 실행됩니다.",
    summary: "Android 15 MediaServer H.265 정수 오버플로. 악성 영상 재생 시 RCE.",
    cvssScore: 8.8,
    severity: "high",
    publishedAt: "2026-03-05T00:00:00Z",
    modifiedAt: "2026-03-07T00:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-9912",
    types: ["RCE"],
    affectedProducts: [
      { vendor: "Google", product: "Android", osFamily: "android", versionRange: "15.0 - 15.2" },
    ],
    references: [
      { url: "https://source.android.com/security/bulletin/2026-03-01", type: "advisory" },
    ],
  },
  {
    id: "11",
    cveId: "CVE-2026-5566",
    title: "iOS WebKit — Memory corruption via malicious SVG",
    description:
      "iOS 18.3 이전의 WebKit 엔진에서 특수 SVG 처리 시 메모리 변조가 발생, 악성 웹페이지 방문만으로 임의 코드 실행이 가능합니다.",
    summary: "iOS 18.3 WebKit 제로데이. 악성 SVG 페이지 방문 시 RCE.",
    cvssScore: 9.0,
    severity: "critical",
    publishedAt: "2026-02-28T00:00:00Z",
    modifiedAt: "2026-03-01T00:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-5566",
    types: ["RCE"],
    affectedProducts: [
      { vendor: "Apple", product: "iOS", osFamily: "ios", versionRange: "< 18.3" },
    ],
    references: [
      { url: "https://support.apple.com/en-us/HT215100", type: "advisory" },
    ],
  },
  {
    id: "12",
    cveId: "CVE-2026-7022",
    title: "GitLab CE/EE — SSRF via import from URL",
    description:
      "GitLab 17.6 이전 버전의 프로젝트 URL 가져오기 기능에서 서버 측 요청 위조(SSRF)가 발생합니다. 내부망 엔드포인트 스캐닝에 악용 가능.",
    summary: "GitLab 17.6 미만 SSRF. 내부망 스캐닝/메타데이터 접근에 악용 가능.",
    cvssScore: 7.7,
    severity: "high",
    publishedAt: "2026-02-20T00:00:00Z",
    modifiedAt: "2026-02-21T00:00:00Z",
    source: "github_advisory",
    sourceUrl: "https://about.gitlab.com/releases/2026/02/20/security-release/",
    types: ["SSRF"],
    affectedProducts: [
      { vendor: "GitLab", product: "GitLab CE/EE", osFamily: "linux", versionRange: "< 17.6" },
    ],
    references: [
      { url: "https://gitlab.com/gitlab-org/cves/-/blob/master/2026/CVE-2026-7022.json", type: "advisory" },
    ],
  },
  {
    id: "13",
    cveId: "CVE-2026-3388",
    title: "Cisco IOS XE — Authentication bypass in Web UI",
    description:
      "Cisco IOS XE의 웹 UI에서 인증 우회 취약점이 발견되어 비인증 원격 공격자가 관리자 권한으로 명령을 실행할 수 있습니다.",
    summary: "Cisco IOS XE 웹 UI 인증 우회. 비인증 RCE. 공공기관 집중 타겟팅 정황.",
    cvssScore: 10.0,
    severity: "critical",
    publishedAt: "2026-02-15T00:00:00Z",
    modifiedAt: "2026-02-16T00:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-3388",
    types: ["Auth", "RCE"],
    affectedProducts: [
      { vendor: "Cisco", product: "IOS XE", osFamily: "other", versionRange: "< 17.14.2" },
    ],
    references: [
      { url: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-2026", type: "advisory" },
    ],
  },
  {
    id: "14",
    cveId: "CVE-2026-1800",
    title: "PostgreSQL — Privilege escalation via CREATE SCHEMA race",
    description:
      "PostgreSQL 17.2 이전 버전의 CREATE SCHEMA 처리에서 권한 체크 레이스가 발생하여 일반 사용자가 다른 스키마 객체에 대한 권한을 우회할 수 있습니다.",
    summary: "PostgreSQL 17.2 미만 CREATE SCHEMA 권한 우회. 권한 분리 정책 무력화 가능.",
    cvssScore: 6.5,
    severity: "medium",
    publishedAt: "2026-02-08T00:00:00Z",
    modifiedAt: "2026-02-10T00:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-1800",
    types: ["Auth"],
    affectedProducts: [
      { vendor: "PostgreSQL", product: "PostgreSQL", osFamily: "linux", versionRange: "< 17.2" },
    ],
    references: [
      { url: "https://www.postgresql.org/support/security/CVE-2026-1800/", type: "advisory" },
    ],
  },
  {
    id: "15",
    cveId: "CVE-2026-0502",
    title: "nginx — Request smuggling via malformed Content-Length",
    description:
      "nginx 1.27 이전 버전이 업스트림 서버로 요청을 전달할 때 Content-Length 헤더를 잘못 파싱하여 요청 밀반입(request smuggling)이 가능합니다.",
    summary: "nginx 1.27 미만 HTTP request smuggling. WAF 우회 및 세션 가로채기 가능.",
    cvssScore: 7.5,
    severity: "high",
    publishedAt: "2026-01-25T00:00:00Z",
    modifiedAt: "2026-01-26T00:00:00Z",
    source: "nvd",
    sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-0502",
    types: ["Auth"],
    affectedProducts: [
      { vendor: "F5", product: "nginx", osFamily: "linux", versionRange: "< 1.27.0" },
    ],
    references: [
      { url: "https://nginx.org/en/security_advisories.html", type: "advisory" },
    ],
  },
];

export function mockSearch(opts: {
  query?: string;
  severity?: string[];
  osFamily?: string[];
  types?: string[];
  fromDate?: string;
  toDate?: string;
}): Vulnerability[] {
  const q = (opts.query ?? "").toLowerCase().trim();
  const fromTs = opts.fromDate ? new Date(opts.fromDate).getTime() : null;
  const toTs = opts.toDate ? new Date(opts.toDate).getTime() + 86400000 : null;

  return MOCK_VULNERABILITIES.filter((v) => {
    if (q) {
      const hay = `${v.cveId} ${v.title} ${v.description} ${v.summary}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (opts.severity?.length && !opts.severity.includes(v.severity)) return false;
    if (opts.osFamily?.length) {
      const osList = v.affectedProducts.map((p) => p.osFamily);
      if (!opts.osFamily.some((o) => osList.includes(o as never))) return false;
    }
    if (opts.types?.length && !opts.types.some((t) => v.types.includes(t as never))) return false;

    const ts = new Date(v.publishedAt).getTime();
    if (fromTs && ts < fromTs) return false;
    if (toTs && ts > toTs) return false;

    return true;
  }).sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime());
}
