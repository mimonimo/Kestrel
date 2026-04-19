export type Severity = "critical" | "high" | "medium" | "low";

export type OsFamily = "windows" | "linux" | "macos" | "android" | "ios" | "other";

export type VulnType = "RCE" | "XSS" | "SQLi" | "CSRF" | "XXE" | "SSRF" | "LFI" | "DoS" | "Auth" | "Other";

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
