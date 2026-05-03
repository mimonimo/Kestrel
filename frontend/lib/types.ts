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

export type Source = "nvd" | "exploit_db" | "github_advisory";

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
  sourceUrl: string;
  types: VulnType[];
  affectedProducts: AffectedProduct[];
  references: Reference[];
}

export interface SearchFilters {
  query?: string;
  severity?: Severity[];
  osFamily?: OsFamily[];
  types?: VulnType[];
  domains?: Domain[];
  fromDate?: string;
  toDate?: string;
}

export interface VulnerabilityListItem {
  cveId: string;
  title: string;
  summary: string | null;
  severity: Severity | null;
  cvssScore: number | null;
  publishedAt: string | null;
  source: Source;
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
