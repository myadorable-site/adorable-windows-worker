/**
 * Step 6 — assemble structured NativeAcceptanceReport and NativeGenerationResult
 * matching backend v0.9A schemas.
 *
 * Evaluates all 5 gates fail-closed:
 * 1. contractValidation
 * 2. sourceSecurity
 * 3. quickGuiCheck
 * 4. quickGuiBuild
 * 5. launchSmokeTest
 *
 * Computes hashes for:
 * - final .exe
 * - preview.png
 * - native-generation-result.json
 * - native-acceptance.json
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadRunResult, saveRunResult } from "./r2.ts";
import type { PeValidationResult } from "./pe-validator.ts";
import type { StepExecutionEvidence } from "./run-step.ts";
import type { SmokeTestResult } from "./smoke.ts";
import type { SecurityScanResult } from "./validate.ts";
import type { ToolchainVerificationResult } from "./verify-toolchain.ts";

export type NativeAcceptanceStatus =
  | "generated"
  | "contract-failed"
  | "security-failed"
  | "check-failed"
  | "build-failed"
  | "launch-failed"
  | "evidence-failed"
  | "visual-failed"
  | "accepted";

export interface NativeAcceptanceEvidence {
  stage:
    | "contract-validation"
    | "source-security"
    | "quickgui-check"
    | "quickgui-build"
    | "launch-smoke-test"
    | "runtime-evidence"
    | "visual-acceptance";
  status: "passed" | "failed" | "skipped";
  timestamp: string;
  contractHash: string;
  sourceBundleHash?: string;
  diagnostics: string[];
  relevantArtifactPath?: string;
  evidenceType: string;
}

export interface NativeAcceptanceGateDecisions {
  contractValidation: "pass" | "fail";
  sourceSecurity: "pass" | "fail";
  quickGuiCheck: "pass" | "fail" | "skipped";
  quickGuiBuild: "pass" | "fail" | "skipped";
  launchSmokeTest: "pass" | "fail" | "skipped";
  runtimeEvidence?: "pass" | "fail" | "skipped";
  visualAcceptance?: "pass" | "fail" | "skipped";
}

export interface NativeAcceptanceReport {
  accepted: boolean;
  status: NativeAcceptanceStatus;
  contractHash: string;
  sourceBundleHash: string;
  quickguiRevision: string;
  targetPlatform: string;
  targetArch: string;
  gateDecisions: NativeAcceptanceGateDecisions;
  blockers: string[];
  evidence: NativeAcceptanceEvidence[];
  toolchain?: {
    repository: string;
    expectedRevision: string;
    verifiedRevision?: string;
    evidence?: string;
    cliPath?: string;
    hostLibraryPath?: string;
    buildStatus?: string;
  };
  artifactHashes: {
    executableSha256?: string;
    previewSha256?: string;
    acceptanceReportSha256?: string;
    generationResultSha256?: string;
    evidenceManifestSha256?: string;
    visualAcceptanceReportSha256?: string;
  };
  runtimeEvidence?: {
    status: "pass" | "fail" | "uncertain" | "skipped";
    manifestRef?: string;
    manifestSha256?: string;
    subResults: {
      startup: "pass" | "fail" | "uncertain" | "skipped";
      navigation: "pass" | "fail" | "uncertain" | "skipped";
      interaction: "pass" | "fail" | "uncertain" | "skipped";
      persistence: "pass" | "fail" | "uncertain" | "skipped";
    };
    blockers?: string[];
  };
  visualAcceptance?: {
    status: "pass" | "fail" | "uncertain" | "skipped";
    contractHash?: string;
    reportRef?: string;
    reportSha256?: string;
    summary?: {
      total: number;
      passed: number;
      failed: number;
      uncertain: number;
    };
    blockers?: string[];
  };
  provenanceDigest: string;
  evaluatedAt: string;
}

export interface NativeGenerationResult {
  generationContractHash: string;
  sourceBundleHash: string;
  quickguiRevision: string;
  targetPlatform: string;
  targetArch: string;
  toolchain?: {
    repository: string;
    expectedRevision: string;
    verifiedRevision?: string;
    evidence?: string;
    cliPath?: string;
    hostLibraryPath?: string;
    buildStatus?: string;
  };
  contractValidation: {
    valid: boolean;
    score: number;
    findings?: Array<{ severity: string; category: string; message: string }>;
  };
  securityScan: {
    ok: boolean;
    findings?: Array<{ code: string; rule: string; path: string }>;
  };
  quickGuiCheck?: {
    success: boolean;
    exitCode: number;
    durationMs: number;
    stdout: string;
    stderr: string;
  };
  quickGuiBuild?: {
    success: boolean;
    exitCode: number;
    durationMs: number;
    stdout: string;
    stderr: string;
    discoveredOutputPaths?: string[];
  };
  launchSmokeTest?: {
    success: boolean;
    aliveStatus: boolean;
    previewCaptured: boolean;
    error?: string;
    pid?: number;
    durationMs?: number;
    windowHandle?: string;
  };
  evidence: NativeAcceptanceEvidence[];
  finalStatus: NativeAcceptanceStatus;
}

export function buildAcceptanceReport(wsDir: string): {
  report: NativeAcceptanceReport;
  generationResult: NativeGenerationResult;
} {
  const run = loadRunResult();
  const now = new Date().toISOString();
  const blockers: string[] = [];
  const evidenceList: NativeAcceptanceEvidence[] = [];

  const contractHash = (run.generationContractHash as string) || "";
  const sourceBundleHash = (run.computedSourceBundleHash as string) || "";
  const quickguiRevision = (run.quickguiRevision as string) || "";
  const targetPlatform = (run.targetPlatform as string) || "windows";
  const targetArch = (run.targetArch as string) || "x64";

  // Gate 1: Contract Validation (Verified at source bundle staging)
  const gate1Pass = Boolean(run.sourceVerified && contractHash && sourceBundleHash);
  if (!gate1Pass) blockers.push("Gate 1 (contractValidation) failed: source bundle provenance or hash verification failed.");
  evidenceList.push({
    stage: "contract-validation",
    status: gate1Pass ? "passed" : "failed",
    timestamp: now,
    contractHash,
    sourceBundleHash,
    diagnostics: gate1Pass ? ["Source bundle and contract provenance verified cleanly."] : ["Provenance mismatch or missing contract."],
    evidenceType: "generation-contract-compliance",
  });

  // Gate 2: Source Security
  const secResult = (run.securityScanResult as SecurityScanResult | undefined);
  const gate2Pass = Boolean(secResult?.ok && run.securityPassed);
  if (!gate2Pass) {
    blockers.push("Gate 2 (sourceSecurity) failed: security scan findings detected in application sources.");
  }
  evidenceList.push({
    stage: "source-security",
    status: gate2Pass ? "passed" : "failed",
    timestamp: now,
    contractHash,
    sourceBundleHash,
    diagnostics: gate2Pass ? ["Security validation passed cleanly."] : (run.securityFindings as string[] || ["Security findings triggered."]),
    evidenceType: "source-security-scan",
  });

  // Toolchain check
  const toolchain = run.quickguiToolchain as ToolchainVerificationResult | undefined;
  if (!toolchain?.verified) {
    blockers.push("QuickGUI toolchain provenance unverified: could not establish exact revision equivalence.");
  }

  // Gate 3: QuickGUI Check
  const checkEv = run.checkEvidence as StepExecutionEvidence | undefined;
  let gate3Decision: "pass" | "fail" | "skipped" = "fail";
  if (checkEv) {
    if (checkEv.exitCode === 0) {
      gate3Decision = "pass";
    } else {
      gate3Decision = "fail";
      blockers.push(`Gate 3 (quickGuiCheck) failed with exit code ${checkEv.exitCode}`);
    }
  } else {
    gate3Decision = "fail";
    blockers.push("Gate 3 (quickGuiCheck) was not executed.");
  }
  evidenceList.push({
    stage: "quickgui-check",
    status: gate3Decision === "pass" ? "passed" : "failed",
    timestamp: now,
    contractHash,
    sourceBundleHash,
    diagnostics: [checkEv?.stderr || checkEv?.stdout || `Exit code ${checkEv?.exitCode ?? -1}`],
    evidenceType: "quickgui-check-runner",
  });

  // Gate 4: QuickGUI Build
  const buildEv = run.buildEvidence as StepExecutionEvidence | undefined;
  const peVal = run.finalPeValidation as PeValidationResult | undefined;
  let gate4Decision: "pass" | "fail" | "skipped" = "fail";
  if (buildEv && buildEv.exitCode === 0 && peVal?.valid) {
    gate4Decision = "pass";
  } else {
    gate4Decision = "fail";
    if (buildEv?.exitCode !== 0) blockers.push(`Gate 4 (quickGuiBuild) failed with exit code ${buildEv?.exitCode}`);
    if (!peVal?.valid) blockers.push(`Gate 4 PE validation failed: ${peVal?.error || "Invalid executable"}`);
  }
  evidenceList.push({
    stage: "quickgui-build",
    status: gate4Decision === "pass" ? "passed" : "failed",
    timestamp: now,
    contractHash,
    sourceBundleHash,
    diagnostics: [
      `Build exit code: ${buildEv?.exitCode ?? -1}`,
      `PE Validation: ${peVal?.valid ? "VALID AMD64 PE" : peVal?.error || "FAILED"}`,
    ],
    evidenceType: "quickgui-build-runner",
  });

  // Gate 5: Launch Smoke Test
  const smoke = run.smokeResult as SmokeTestResult | undefined;
  let gate5Decision: "pass" | "fail" | "skipped" = "fail";
  if (smoke?.passed && smoke.aliveStatus && smoke.previewCaptured) {
    gate5Decision = "pass";
  } else {
    gate5Decision = "fail";
    blockers.push(`Gate 5 (launchSmokeTest) failed: ${smoke?.errorMessage || "Process did not remain active or window not captured"}`);
  }
  evidenceList.push({
    stage: "launch-smoke-test",
    status: gate5Decision === "pass" ? "passed" : "failed",
    timestamp: now,
    contractHash,
    sourceBundleHash,
    diagnostics: [
      `Alive: ${smoke?.aliveStatus ? "yes" : "no"}`,
      `Preview captured: ${smoke?.previewCaptured ? "yes" : "no"}`,
      smoke?.errorMessage || "Window rendered and captured",
    ],
    evidenceType: "native-launcher-smoke",
  });

  // Gate 6: Runtime Evidence
  const evidenceRes = run.runtimeEvidenceResult as {
    status?: "PASS" | "FAIL" | "UNCERTAIN";
    manifestPath?: string;
    manifestSha256?: string;
    subResults?: {
      startup: "pass" | "fail" | "uncertain" | "skipped";
      navigation: "pass" | "fail" | "uncertain" | "skipped";
      interaction: "pass" | "fail" | "uncertain" | "skipped";
      persistence: "pass" | "fail" | "uncertain" | "skipped";
    };
    evidenceCount?: number;
    exeSha256?: string;
  } | undefined;

  let gate6Decision: "pass" | "fail" | "skipped" = "skipped";
  if (evidenceRes) {
    if (evidenceRes.status === "PASS") {
      gate6Decision = "pass";
    } else {
      gate6Decision = "fail";
      blockers.push(`Gate 6 (runtimeEvidence) failed with status "${evidenceRes.status}".`);
    }

    evidenceList.push({
      stage: "runtime-evidence",
      status: gate6Decision === "pass" ? "passed" : "failed",
      timestamp: now,
      contractHash,
      sourceBundleHash,
      diagnostics: [
        `Overall status: ${evidenceRes.status}`,
        `Manifest SHA: ${evidenceRes.manifestSha256 || "none"}`,
        `Evidence count: ${evidenceRes.evidenceCount || 0}`,
        `Startup: ${evidenceRes.subResults?.startup || "unknown"}`,
        `Navigation: ${evidenceRes.subResults?.navigation || "unknown"}`,
        `Interaction: ${evidenceRes.subResults?.interaction || "unknown"}`,
        `Persistence: ${evidenceRes.subResults?.persistence || "unknown"}`,
      ],
      relevantArtifactPath: evidenceRes.manifestPath,
      evidenceType: "runtime-evidence-manifest",
    });
  }

  // Gate 7: Visual Acceptance
  const visualRes = run.visualAcceptanceResult as {
    status?: "PASS" | "FAIL" | "UNCERTAIN";
    reportPath?: string;
    reportSha256?: string;
    summary?: {
      total: number;
      passed: number;
      failed: number;
      uncertain: number;
    };
    contractHash?: string;
  } | undefined;

  let gate7Decision: "pass" | "fail" | "skipped" = "skipped";
  if (visualRes) {
    if (visualRes.status === "PASS") {
      gate7Decision = "pass";
    } else {
      gate7Decision = "fail";
      blockers.push(`Gate 7 (visualAcceptance) failed with status "${visualRes.status}".`);
    }

    evidenceList.push({
      stage: "visual-acceptance",
      status: gate7Decision === "pass" ? "passed" : "failed",
      timestamp: now,
      contractHash,
      sourceBundleHash,
      diagnostics: [
        `Overall status: ${visualRes.status}`,
        `Report SHA: ${visualRes.reportSha256 || "none"}`,
        `Passed: ${visualRes.summary?.passed ?? 0}/${visualRes.summary?.total ?? 0}`,
        `Failed: ${visualRes.summary?.failed ?? 0}`,
        `Uncertain: ${visualRes.summary?.uncertain ?? 0}`,
      ],
      relevantArtifactPath: visualRes.reportPath,
      evidenceType: "visual-acceptance-report",
    });
  }

  // Decisions & Final Status
  const gateDecisions: NativeAcceptanceGateDecisions = {
    contractValidation: gate1Pass ? "pass" : "fail",
    sourceSecurity: gate2Pass ? "pass" : "fail",
    quickGuiCheck: gate3Decision,
    quickGuiBuild: gate4Decision,
    launchSmokeTest: gate5Decision,
    runtimeEvidence: gate6Decision,
    visualAcceptance: gate7Decision,
  };

  let status: NativeAcceptanceStatus;
  let accepted = false;

  if (!gate1Pass || !toolchain?.verified) {
    status = "contract-failed";
  } else if (!gate2Pass) {
    status = "security-failed";
  } else if (gate3Decision === "fail") {
    status = "check-failed";
  } else if (gate4Decision === "fail") {
    status = "build-failed";
  } else if (gate5Decision === "fail") {
    status = "launch-failed";
  } else if (gate6Decision === "fail") {
    status = "evidence-failed";
  } else if (gate7Decision === "fail") {
    status = "visual-failed";
  } else if (
    gate1Pass &&
    gate2Pass &&
    gate3Decision === "pass" &&
    gate4Decision === "pass" &&
    gate5Decision === "pass" &&
    (gate6Decision === "pass" || gate6Decision === "skipped") &&
    (gate7Decision === "pass" || gate7Decision === "skipped")
  ) {
    status = "accepted";
    accepted = true;
  } else {
    status = "generated";
  }

  // Non-circular Provenance Digest
  const artifactSha256 = peVal?.sha256 || "";
  const provString = [
    `generationContractHash:${contractHash}`,
    `sourceBundleHash:${sourceBundleHash}`,
    `quickGuiRepository:https://github.com/egoist/quickgui.git`,
    `quickGuiRevision:${quickguiRevision}`,
    `targetPlatform:${targetPlatform}`,
    `targetArch:${targetArch}`,
    `artifactSha256:${artifactSha256}`,
  ].join("\n");
  const provenanceDigest = createHash("sha256").update(provString, "utf8").digest("hex");

  const toolchainMeta = toolchain ? {
    repository: toolchain.repository || "https://github.com/egoist/quickgui.git",
    expectedRevision: toolchain.expectedRevision || "0a5007a03be4a0ba08c7da27010f74699711255",
    verifiedRevision: toolchain.verifiedRevision,
    evidence: toolchain.evidence,
    cliPath: toolchain.cliPath,
    hostLibraryPath: toolchain.hostLibraryPath,
    buildStatus: toolchain.buildStatus || (toolchain.verified ? "built" : undefined),
  } : undefined;

  const generationResult: NativeGenerationResult = {
    generationContractHash: contractHash,
    sourceBundleHash,
    quickguiRevision,
    targetPlatform,
    targetArch,
    toolchain: toolchainMeta,
    contractValidation: {
      valid: gate1Pass,
      score: gate1Pass ? 1.0 : 0.0,
    },
    securityScan: {
      ok: gate2Pass,
      findings: secResult?.findings || [],
    },
    quickGuiCheck: checkEv ? {
      success: checkEv.exitCode === 0,
      exitCode: checkEv.exitCode,
      durationMs: checkEv.durationMs,
      stdout: checkEv.stdout,
      stderr: checkEv.stderr,
    } : undefined,
    quickGuiBuild: buildEv ? {
      success: buildEv.exitCode === 0,
      exitCode: buildEv.exitCode,
      durationMs: buildEv.durationMs,
      stdout: buildEv.stdout,
      stderr: buildEv.stderr,
      discoveredOutputPaths: buildEv.discoveredOutputPaths,
    } : undefined,
    launchSmokeTest: smoke ? {
      success: smoke.passed,
      aliveStatus: smoke.aliveStatus,
      previewCaptured: smoke.previewCaptured,
      error: smoke.errorMessage,
      pid: smoke.pid,
      durationMs: smoke.settleDurationMs,
      windowHandle: smoke.windowHandle,
    } : undefined,
    evidence: evidenceList,
    finalStatus: status,
  };

  const report: NativeAcceptanceReport = {
    accepted,
    status,
    contractHash,
    sourceBundleHash,
    quickguiRevision,
    targetPlatform,
    targetArch,
    toolchain: toolchainMeta,
    gateDecisions,
    blockers,
    evidence: evidenceList,
    artifactHashes: {
      executableSha256: artifactSha256,
      previewSha256: smoke?.previewSha256,
      evidenceManifestSha256: evidenceRes?.manifestSha256,
      visualAcceptanceReportSha256: visualRes?.reportSha256,
    },
    runtimeEvidence: evidenceRes ? {
      status: evidenceRes.status === "PASS" ? "pass" : evidenceRes.status === "FAIL" ? "fail" : "uncertain",
      manifestRef: "runtime-evidence/manifest.json",
      manifestSha256: evidenceRes.manifestSha256,
      subResults: evidenceRes.subResults ?? {
        startup: "skipped",
        navigation: "skipped",
        interaction: "skipped",
        persistence: "skipped",
      },
    } : undefined,
    visualAcceptance: visualRes ? {
      status: visualRes.status === "PASS" ? "pass" : visualRes.status === "FAIL" ? "fail" : "uncertain",
      contractHash: visualRes.contractHash,
      reportRef: "artifacts/visual-acceptance.json",
      reportSha256: visualRes.reportSha256,
      summary: visualRes.summary,
    } : undefined,
    provenanceDigest,
    evaluatedAt: now,
  };

  // Write acceptance files into artifacts/
  const artifactsDir = join(wsDir, "artifacts");
  mkdirSync(artifactsDir, { recursive: true });

  const genResultPath = join(artifactsDir, "native-generation-result.json");
  const acceptancePath = join(artifactsDir, "native-acceptance.json");

  const genResultJson = JSON.stringify(generationResult, null, 2);
  writeFileSync(genResultPath, genResultJson, "utf8");
  report.artifactHashes.generationResultSha256 = createHash("sha256").update(genResultJson).digest("hex");

  const acceptanceJson = JSON.stringify(report, null, 2);
  writeFileSync(acceptancePath, acceptanceJson, "utf8");
  report.artifactHashes.acceptanceReportSha256 = createHash("sha256").update(acceptanceJson).digest("hex");

  saveRunResult({
    nativeAcceptanceReport: report,
    nativeGenerationResult: generationResult,
    acceptanceStatus: status,
    accepted,
    artifactHashes: report.artifactHashes,
    provenanceDigest,
  });

  console.log(`[Acceptance] Evaluated 5 gates: status="${status}", accepted=${accepted}. Blockers: ${blockers.length}`);
  return { report, generationResult };
}

if (import.meta.main) {
  const wsDir = loadRunResult().wsDir;
  buildAcceptanceReport(wsDir);
}
