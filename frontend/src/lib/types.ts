export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Vulnerability {
  id: string;
  rule_id: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line_start: number;
  line_end: number;
  code_snippet: string;
  category: string;
  cwe_id?: string;
  recommendation: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanResult {
  scan_id: string;
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
  scanned_at: string;
  language: string;
  filename: string;
}

export interface ScanRequest {
  code: string;
  language: string;
  filename?: string;
}

export interface Patch {
  vulnerability_id: string;
  original_code: string;
  patched_code: string;
  explanation: string;
  confidence: number;
}

export interface PatchResult {
  scan_id: string;
  patches: Patch[];
  patched_code_full: string;
  ai_available: boolean;
}

export interface PatchRequest {
  code: string;
  vulnerabilities: Vulnerability[];
  scan_id: string;
}

export interface RescanRequest {
  code: string;
  language: string;
}

export interface ReportRequest {
  scan_id: string;
  original_code: string;
  patched_code?: string;
  vulnerabilities: Vulnerability[];
  patches?: Patch[];
}

export interface HealthResponse {
  status: string;
  version: string;
  ai_available: boolean;
  scanners_available: string[];
}
