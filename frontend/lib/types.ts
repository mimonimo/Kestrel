export type Severity = "critical" | "high" | "medium" | "low";

export type OsFamily = "windows" | "linux" | "macos" | "android" | "ios" | "other";

// Mechanism-class taxonomy. The backend keeps this as free-form
// strings on `vulnerability_types.name`, so adding new chips here is a
// frontend-only change — no migration. Domain/component categorization
// (audio / SSH / kernel / browser / …) lives in PR-B with its own table.
export type VulnType =
  | "RCE"
  | "XSS"
  | "SQLi"
  | "CSRF"
  | "XXE"
  | "SSRF"
  | "LFI"
  | "Path-Traversal"
  | "Deserialization"
  | "Open-Redirect"
  | "Privilege-Escalation"
  | "Info-Disclosure"
  | "Memory-Corruption"
  | "DoS"
  | "Auth"
  | "Other";

// FilterPanel 의 취약점 유형 칩이 facets 응답을 기다리지 않고 즉시 표시되도록
// 자주 보이는 유형들을 hardcoded default 로 보존. facets 응답이 도착하면
// dynamic 목록과 merge 되어 카운트가 채워진다.
export const DEFAULT_VULN_TYPES: VulnType[] = [
  "RCE",
  "XSS",
  "SQLi",
  "Memory-Corruption",
  "Info-Disclosure",
  "Auth",
  "DoS",
  "Path-Traversal",
];

// Cross-domain technology surface (PR 10-B). A CVE can carry multiple
// — e.g. an audio codec parser bug embedded in an SSH client gets both
// `media` and `auth`. Backend infers these at ingestion time and stores
// them in `vulnerabilities.domains TEXT[]`. Frontend treats this as a
// closed set so the chip group order is stable; mismatches between
// frontend and backend domain vocab are intentionally invisible (chip
// just won't render). Keep in sync with `app.services.domain_classifier.DOMAINS`.
export type Domain =
  | "kernel"
  | "os"
  | "browser"
  | "web-server"
  | "web-framework"
  | "database"
  | "media"
  | "network"
  | "mail"
  | "auth"
  | "crypto"
  | "runtime"
  | "mobile"
  | "virtualization"
  | "office"
  | "enterprise"
  | "iot"
  | "messaging";

export const DOMAINS: readonly Domain[] = [
  "kernel",
  "os",
  "browser",
  "web-server",
  "web-framework",
  "database",
  "media",
  "network",
  "mail",
  "auth",
  "crypto",
  "runtime",
  "mobile",
  "virtualization",
  "office",
  "enterprise",
  "iot",
  "messaging",
] as const;

export type Source = "nvd" | "exploit_db" | "github_advisory" | "mitre";

export interface AffectedProduct {
  vendor: string;
  product: string;
  osFamily: OsFamily;
  versionRange: string;
  cpe?: string;
}

export interface Reference {
  url: string;
  type: "advisory" | "exploit" | "patch" | "writeup";
}

export interface Vulnerability {
  id: string;
  cveId: string;
  title: string;
  description: string;
  summary: string;
  cvssScore: number;
  cvssVector?: string;
  severity: Severity;
  publishedAt: string;
  modifiedAt: string;
  source: Source;
  sources: Source[];
  sourceUrl: string;
  types: VulnType[];
  affectedProducts: AffectedProduct[];
  references: Reference[];
  epssScore?: number | null;
  epssPercentile?: number | null;
  kevListed?: boolean;
  kevDateAdded?: string | null;
  kevDueDate?: string | null;
  enrichment?: Enrichment | null;
}

export interface CpeMatch {
  criteria: string;
  vulnerable: boolean;
  versionStartIncluding?: string | null;
  versionStartExcluding?: string | null;
  versionEndIncluding?: string | null;
  versionEndExcluding?: string | null;
}

export interface ReferencePreview {
  url: string;
  title?: string | null;
  description?: string | null;
  siteName?: string | null;
  ok: boolean;
}

export interface RelatedCve {
  cveId: string;
  title: string;
  severity?: Severity | null;
  cvssScore?: number | null;
  publishedAt?: string | null;
  kevListed?: boolean;
  reason: string;
}

export interface Weakness {
  cweId: string;
  name?: string | null;
  url?: string | null;
}

export interface EnrichedRef {
  url: string;
  tags: string[];
  source?: string | null;
}

export interface CvssMetric {
  version: string;
  vector?: string | null;
  baseScore?: number | null;
  baseSeverity?: string | null;
  source?: string | null;
  kind?: string | null;
  exploitabilityScore?: number | null;
  impactScore?: number | null;
  exploitMaturity?: string | null;
}

export interface Enrichment {
  weaknesses: Weakness[];
  references: EnrichedRef[];
  metrics: CvssMetric[];
  cpeMatches?: CpeMatch[];
  vulnStatus?: string | null;
  cna?: string | null;
}

export type PriorityTier =
  | "kev"
  | "epss_high"
  | "cvss_mid_epss_high"
  | "cvss_high_epss_low";

export interface SearchFilters {
  query?: string;
  severity?: Severity[];
  osFamily?: OsFamily[];
  types?: VulnType[];
  domains?: Domain[];
  fromDate?: string;
  toDate?: string;
  priority?: PriorityTier;
}

export interface VulnerabilityListItem {
  cveId: string;
  title: string;
  summary: string | null;
  severity: Severity | null;
  cvssScore: number | null;
  publishedAt: string | null;
  source: Source;
  // PR 10-AF: every upstream feed contributing data — MITRE alone, NVD
  // alone, both together, etc. ``source`` (singular) stays as primary
  // attribution; this array drives the multi-source badge cluster.
  sources: Source[];
  types: string[];
  osFamilies: string[];
  domains: string[];
}

export interface SearchResponse {
  items: VulnerabilityListItem[];
  total: number;
  page: number;
  pageSize: number;
}

export interface IngestionSnapshot {
  source: Source;
  finishedAt: string | null;
  status: string;
  itemsProcessed: number;
  errorMessage: string | null;
}

export interface StatusReport {
  api: boolean;
  db: boolean;
  redis: boolean;
  meili: boolean;
  nvdKeyPresent: boolean;
  githubTokenPresent: boolean;
  ingestions: IngestionSnapshot[];
  serverTime: string;
}
