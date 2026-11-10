import {
  ScanResult,
  PatchResult,
  ReportRequest,
  Vulnerability,
  HealthResponse,
} from "./types";
import { clientScan, clientPatch, clientReportBlob } from "./client-scanner";

const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

function shouldUseClientFallback(): boolean {
  if (typeof window === "undefined") return false;
  // If hosted on HTTPS (like GitHub Pages) and API_URL points to localhost HTTP,
  // browsers strictly block mixed active content. Fall back immediately with 0 delay.
  return window.location.protocol === "https:" && API_URL.startsWith("http://localhost");
}

// ---------------------------------------------------------------------------
// Generic fetch helper with fallback awareness
// ---------------------------------------------------------------------------

async function apiFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  if (shouldUseClientFallback()) {
    throw new Error("Mixed content prevented HTTP localhost fetch on HTTPS static host");
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2500);

  try {
    const res = await fetch(`${API_URL}${path}`, {
      headers: { "Content-Type": "application/json", ...options.headers },
      signal: controller.signal,
      ...options,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const body = await res.json();
        detail = body?.detail || detail;
      } catch {
        /* ignore */
      }
      throw new Error(detail);
    }

    return res.json() as Promise<T>;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// API functions with seamless client-side fallback for GitHub Pages
// ---------------------------------------------------------------------------

export async function checkHealth(): Promise<HealthResponse> {
  try {
    return await apiFetch<HealthResponse>("/health");
  } catch {
    return {
      status: "client_fallback",
      version: "1.0.0",
      ai_available: false,
      scanners_available: ["sql_injection", "hardcoded_creds", "unsafe_eval", "python_static"],
    };
  }
}

export async function scanCode(
  code: string,
  language: string,
  filename?: string
): Promise<ScanResult> {
  try {
    return await apiFetch<ScanResult>("/scan", {
      method: "POST",
      body: JSON.stringify({ code, language, filename }),
    });
  } catch (err) {
    console.warn("Backend unavailable, using client-side security scanner fallback:", err);
    return clientScan(code, language, filename);
  }
}

export async function generatePatches(
  code: string,
  vulnerabilities: Vulnerability[],
  scan_id: string
): Promise<PatchResult> {
  try {
    return await apiFetch<PatchResult>("/patch", {
      method: "POST",
      body: JSON.stringify({ code, vulnerabilities, scan_id }),
    });
  } catch (err) {
    console.warn("Backend unavailable, using client-side patch generator fallback:", err);
    return clientPatch(code, vulnerabilities, scan_id);
  }
}

export async function rescanCode(
  code: string,
  language: string
): Promise<ScanResult> {
  try {
    return await apiFetch<ScanResult>("/rescan", {
      method: "POST",
      body: JSON.stringify({ code, language }),
    });
  } catch (err) {
    console.warn("Backend unavailable, using client-side rescan fallback:", err);
    return clientScan(code, language, "patched_code.py");
  }
}

export async function generateReport(request: ReportRequest): Promise<Blob> {
  if (shouldUseClientFallback()) {
    return clientReportBlob(request);
  }
  try {
    const res = await fetch(`${API_URL}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    return await res.blob();
  } catch (err) {
    console.warn("Backend unavailable, generating client-side report download:", err);
    return clientReportBlob(request);
  }
}
