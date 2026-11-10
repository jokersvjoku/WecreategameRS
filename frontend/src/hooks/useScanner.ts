"use client";
import { useState, useCallback } from "react";
import { ScanResult, PatchResult, Vulnerability } from "@/lib/types";
import { scanCode, generatePatches, rescanCode, generateReport } from "@/lib/api";

interface ScannerState {
  code: string;
  language: string;
  filename: string;
  scanResult: ScanResult | null;
  patchResult: PatchResult | null;
  rescanResult: ScanResult | null;
  isScanning: boolean;
  isPatching: boolean;
  isRescanning: boolean;
  error: string | null;
}

export function useScanner() {
  const [state, setState] = useState<ScannerState>({
    code: "",
    language: "python",
    filename: "uploaded_code.py",
    scanResult: null,
    patchResult: null,
    rescanResult: null,
    isScanning: false,
    isPatching: false,
    isRescanning: false,
    error: null,
  });

  const setCode = useCallback((code: string) => {
    setState((s) => ({ ...s, code, error: null }));
  }, []);

  const setLanguage = useCallback((language: string) => {
    setState((s) => ({ ...s, language }));
  }, []);

  const setFilename = useCallback((filename: string) => {
    setState((s) => ({ ...s, filename }));
  }, []);

  const scan = useCallback(async (): Promise<ScanResult | null> => {
    if (!state.code.trim()) {
      setState((s) => ({ ...s, error: "Please enter code before scanning." }));
      return null;
    }
    setState((s) => ({ ...s, isScanning: true, error: null, scanResult: null }));
    try {
      const result = await scanCode(state.code, state.language, state.filename);
      setState((s) => ({ ...s, scanResult: result, isScanning: false }));
      // Persist for cross-page access
      sessionStorage.setItem(`scan_${result.scan_id}`, JSON.stringify(result));
      sessionStorage.setItem(`code_${result.scan_id}`, state.code);
      return result;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Scan failed.";
      setState((s) => ({ ...s, error: msg, isScanning: false }));
      return null;
    }
  }, [state.code, state.language, state.filename]);

  const patch = useCallback(
    async (vulns?: Vulnerability[]): Promise<PatchResult | null> => {
      const { scanResult } = state;
      if (!scanResult) {
        setState((s) => ({ ...s, error: "Run a scan before generating patches." }));
        return null;
      }
      setState((s) => ({ ...s, isPatching: true, error: null }));
      try {
        const result = await generatePatches(
          state.code,
          vulns ?? scanResult.vulnerabilities,
          scanResult.scan_id
        );
        setState((s) => ({ ...s, patchResult: result, isPatching: false }));
        sessionStorage.setItem(`patch_${scanResult.scan_id}`, JSON.stringify(result));
        return result;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Patch generation failed.";
        setState((s) => ({ ...s, error: msg, isPatching: false }));
        return null;
      }
    },
    [state]
  );

  const rescan = useCallback(async (): Promise<ScanResult | null> => {
    const { patchResult } = state;
    if (!patchResult) {
      setState((s) => ({ ...s, error: "Generate patches before re-scanning." }));
      return null;
    }
    setState((s) => ({ ...s, isRescanning: true, error: null }));
    try {
      const result = await rescanCode(patchResult.patched_code_full, state.language);
      setState((s) => ({ ...s, rescanResult: result, isRescanning: false }));
      return result;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Re-scan failed.";
      setState((s) => ({ ...s, error: msg, isRescanning: false }));
      return null;
    }
  }, [state]);

  const downloadReport = useCallback(async (): Promise<void> => {
    const { scanResult, patchResult } = state;
    if (!scanResult) {
      setState((s) => ({ ...s, error: "No scan result to report on." }));
      return;
    }
    try {
      const blob = await generateReport({
        scan_id: scanResult.scan_id,
        original_code: state.code,
        patched_code: patchResult?.patched_code_full,
        vulnerabilities: scanResult.vulnerabilities,
        patches: patchResult?.patches,
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `patchpilot-report-${scanResult.scan_id.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Report generation failed.";
      setState((s) => ({ ...s, error: msg }));
    }
  }, [state]);

  const clearError = useCallback(() => {
    setState((s) => ({ ...s, error: null }));
  }, []);

  return {
    ...state,
    setCode,
    setLanguage,
    setFilename,
    scan,
    patch,
    rescan,
    downloadReport,
    clearError,
  };
}
