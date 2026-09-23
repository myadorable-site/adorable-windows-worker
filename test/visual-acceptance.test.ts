import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  computeLuminance,
  parseIhdr,
  runVisualAcceptance,
  sampleLuminance,
  validatePngHeader,
  type VisualAcceptanceContract,
} from "../scripts/visual-acceptance.ts";
import { buildCallbackPayload } from "../scripts/report.ts";
import { buildAcceptanceReport } from "../scripts/generate-acceptance.ts";
import { saveRunResult } from "../scripts/r2.ts";

function createChunk(type: string, data: Uint8Array): Uint8Array {
  const len = data.length;
  const chunk = new Uint8Array(12 + len);
  chunk[0] = (len >> 24) & 0xff;
  chunk[1] = (len >> 16) & 0xff;
  chunk[2] = (len >> 8) & 0xff;
  chunk[3] = len & 0xff;
  for (let i = 0; i < 4; i++) chunk[4 + i] = type.charCodeAt(i);
  chunk.set(data, 8);
  // CRC-32 (dummy for detector tests since zlib checks IDAT, not PNG CRC)
  return chunk;
}

function createSyntheticPng(width: number, height: number, color: { r: number; g: number; b: number }): Uint8Array {
  const header = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

  const ihdrData = new Uint8Array(13);
  ihdrData[0] = (width >> 24) & 0xff;
  ihdrData[1] = (width >> 16) & 0xff;
  ihdrData[2] = (width >> 8) & 0xff;
  ihdrData[3] = width & 0xff;
  ihdrData[4] = (height >> 24) & 0xff;
  ihdrData[5] = (height >> 16) & 0xff;
  ihdrData[6] = (height >> 8) & 0xff;
  ihdrData[7] = height & 0xff;
  ihdrData[8] = 8; // 8-bit depth
  ihdrData[9] = 2; // RGB
  ihdrData[10] = 0;
  ihdrData[11] = 0;
  ihdrData[12] = 0;

  const ihdrChunk = createChunk("IHDR", ihdrData);

  const rawData = new Uint8Array((1 + width * 3) * height);
  let p = 0;
  for (let y = 0; y < height; y++) {
    rawData[p++] = 0;
    for (let x = 0; x < width; x++) {
      rawData[p++] = color.r;
      rawData[p++] = color.g;
      rawData[p++] = color.b;
    }
  }

  const compressed = deflateSync(rawData);
  const idatChunk = createChunk("IDAT", compressed);
  const iendChunk = createChunk("IEND", new Uint8Array(0));

  const totalLength = header.length + ihdrChunk.length + idatChunk.length + iendChunk.length;
  const out = new Uint8Array(totalLength);
  let offset = 0;
  out.set(header, offset);
  offset += header.length;
  out.set(ihdrChunk, offset);
  offset += ihdrChunk.length;
  out.set(idatChunk, offset);
  offset += idatChunk.length;
  out.set(iendChunk, offset);

  return out;
}

describe("Decision Harness v0.9C.2 — Worker Visual Acceptance Runner", () => {
  const tmpDir = join(import.meta.dir, ".tmp-visual-test-" + Date.now());
  const wsDir = join(tmpDir, "ws");
  const distDir = join(wsDir, "dist", "windows-x64");
  const fakeExePath = join(distDir, "FinanceTracker.exe");
  const originalEnv = { ...process.env };

  const validPng = createSyntheticPng(1024, 768, { r: 24, g: 24, b: 27 }); // dark zinc-900

  beforeEach(() => {
    mkdirSync(distDir, { recursive: true });
    process.env.RUNNER_TEMP = tmpDir;
    process.env.ADORABLE_JOB_ID = "job_test_visual";
    process.env.ADORABLE_APP_ID = "com.adorable.financetracker";
    process.env.ADORABLE_BUILD_ID = "build_test_visual";
    process.env.ADORABLE_TARGET_PLATFORM = "windows";
    process.env.ADORABLE_TARGET_ARCH = "x64";
    process.env.ADORABLE_GENERATION_CONTRACT_HASH = "h-e44a337649b66028";
    process.env.ADORABLE_SOURCE_BUNDLE_SHA256 = "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1";
    process.env.ADORABLE_QUICKGUI_REVISION = "0a5007a03be4a0ba08c7da27010f74699711255";

    // Create a dummy executable
    const dummyExe = Buffer.alloc(1024 * 1024 + 100);
    dummyExe[0] = 0x4d; // 'M'
    dummyExe[1] = 0x5a; // 'Z'
    writeFileSync(fakeExePath, dummyExe);
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it("1. validatePngHeader & parseIhdr correctly inspect PNG headers and dimensions", () => {
    expect(validatePngHeader(validPng)).toBe(true);
    expect(validatePngHeader(new Uint8Array([]))).toBe(false);
    expect(validatePngHeader(new Uint8Array([0x89, 0x50, 0x4e]))).toBe(false);

    const ihdr = parseIhdr(validPng);
    expect(ihdr).not.toBeNull();
    expect(ihdr?.width).toBe(1024);
    expect(ihdr?.height).toBe(768);
    expect(ihdr?.bitDepth).toBe(8);
    expect(ihdr?.colorType).toBe(2);

    expect(parseIhdr(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))).toBeNull();
  });

  it("2. computeLuminance and sampleLuminance compute valid WCAG luminance", () => {
    const blackLum = computeLuminance(0, 0, 0);
    const whiteLum = computeLuminance(255, 255, 255);
    expect(blackLum).toBeCloseTo(0, 4);
    expect(whiteLum).toBeCloseTo(1, 4);

    const darkPng = createSyntheticPng(100, 100, { r: 20, g: 20, b: 20 });
    const lum = sampleLuminance(darkPng);
    expect(lum).toBeLessThan(0.3); // dark theme
  });

  it("3. runVisualAcceptance passes cleanly when screenshots match contract and manifest", async () => {
    const screenshotsDir = join(wsDir, "runtime-evidence", "screenshots");
    mkdirSync(screenshotsDir, { recursive: true });

    // Canonical screens for Finance Tracker
    const screens = [
      { scenarioId: "startup", stepId: "startup-screenshot", fileName: "startup-startup-screenshot.png" },
      { scenarioId: "nav-transactions", stepId: "nav-transactions-screenshot", fileName: "nav-transactions-nav-transactions-screenshot.png" },
      { scenarioId: "nav-budgets", stepId: "nav-budgets-screenshot", fileName: "nav-budgets-nav-budgets-screenshot.png" },
      { scenarioId: "nav-recurring", stepId: "nav-recurring-screenshot", fileName: "nav-recurring-nav-recurring-screenshot.png" },
    ];

    const allEvidence: any[] = [];
    for (const scr of screens) {
      const fullPath = join(screenshotsDir, scr.fileName);
      writeFileSync(fullPath, validPng);
      const sha = createHash("sha256").update(validPng).digest("hex");
      allEvidence.push({
        evidenceId: `ev-${scr.fileName}`,
        type: "screenshot",
        sha256: sha,
        relativePath: `screenshots/${scr.fileName}`,
        sizeBytes: validPng.length,
        scenarioId: scr.scenarioId,
        stepId: scr.stepId,
        capturedAt: new Date().toISOString(),
      });
    }

    const manifest = {
      manifestVersion: "0.9C.1",
      jobId: "job_test_visual",
      buildId: "build_test_visual",
      appId: "com.adorable.financetracker",
      generationContractHash: "h-e44a337649b66028",
      sourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
      runtimeEvidenceContractHash: "rec-618779c1e13998f5",
      exeSha256: createHash("sha256").update(readFileSync(fakeExePath)).digest("hex"),
      targetPlatform: "windows",
      targetArch: "x64",
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: 500,
      scenarios: [
        {
          scenarioId: "scenario-startup",
          kind: "STARTUP",
          status: "PASS",
          stepCount: 1,
          evidenceCount: 1,
        },
        {
          scenarioId: "scenario-navigation",
          kind: "NAVIGATION",
          status: "PASS",
          stepCount: 3,
          evidenceCount: 3,
        },
      ],
      evidence: allEvidence,
      summary: { totalScenarios: 2, passedScenarios: 2, failedScenarios: 0, uncertainScenarios: 0, totalEvidenceRecords: allEvidence.length },
      environment: { os: "Windows_NT", release: "10.0.26100", arch: "x64", cpus: 4, memoryTotalGb: 16 },
      overallStatus: "PASS",
      subResults: { startup: "pass", navigation: "pass", interaction: "pass", persistence: "pass" },
    };

    const evidenceDir = join(wsDir, "runtime-evidence");
    mkdirSync(evidenceDir, { recursive: true });
    writeFileSync(join(evidenceDir, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8");

    saveRunResult({
      wsDir,
      finalExe: fakeExePath,
      generationContractHash: "h-e44a337649b66028",
      sourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
      runtimeEvidenceResult: {
        status: "pass",
        manifestPath: join(evidenceDir, "manifest.json"),
        manifestSha256: "manifest-sha",
        subResults: manifest.subResults,
      },
    });

    const result = await runVisualAcceptance();
    expect(result.passed).toBe(true);
    expect(result.report.overallStatus).toBe("PASS");
    expect(result.report.failedObligations).toBe(0);
    expect(result.report.summary.passed).toBeGreaterThan(0);
    expect(result.report.contractHash).toBe("vac-b917446605c0b66d");
    expect(result.reportSha256).toBeDefined();
  });

  it("4. runVisualAcceptance fails closed when a required screenshot is missing", async () => {
    const screenshotsDir = join(wsDir, "runtime-evidence", "screenshots");
    mkdirSync(screenshotsDir, { recursive: true });

    // Only 1 screenshot provided, 3 missing
    const f = "scenario-startup-step-initial-render.png";
    writeFileSync(join(screenshotsDir, f), validPng);
    const sha = createHash("sha256").update(validPng).digest("hex");

    const partialEvidence = [
      {
        evidenceId: `ev-${f}`,
        type: "screenshot",
        sha256: sha,
        relativePath: `screenshots/${f}`,
        sizeBytes: validPng.length,
        scenarioId: "scenario-startup",
        stepId: "initial-render",
        capturedAt: new Date().toISOString(),
      },
    ];

    const manifest = {
      manifestVersion: "0.9C.1",
      jobId: "job_test_visual",
      buildId: "build_test_visual",
      appId: "com.adorable.financetracker",
      generationContractHash: "h-e44a337649b66028",
      sourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
      runtimeEvidenceContractHash: "rec-618779c1e13998f5",
      exeSha256: createHash("sha256").update(readFileSync(fakeExePath)).digest("hex"),
      targetPlatform: "windows",
      targetArch: "x64",
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: 500,
      scenarios: [],
      evidence: partialEvidence,
      summary: { totalScenarios: 1, passedScenarios: 1, failedScenarios: 0, uncertainScenarios: 0, totalEvidenceRecords: 1 },
      environment: { os: "Windows_NT", release: "10.0.26100", arch: "x64", cpus: 4, memoryTotalGb: 16 },
      overallStatus: "PASS",
      subResults: { startup: "pass", navigation: "pass", interaction: "pass", persistence: "pass" },
    };

    const evidenceDir = join(wsDir, "runtime-evidence");
    mkdirSync(evidenceDir, { recursive: true });
    writeFileSync(join(evidenceDir, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8");

    saveRunResult({
      wsDir,
      finalExe: fakeExePath,
      generationContractHash: "h-e44a337649b66028",
      sourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
    });

    const result = await runVisualAcceptance();
    expect(result.passed).toBe(false);
    expect(result.report.overallStatus).toBe("FAIL");
    expect(result.report.failedObligations).toBeGreaterThan(0);
  });

  it("5. Gate 7 integration in buildAcceptanceReport sets visual-failed on visual failure", () => {
    saveRunResult({
      wsDir,
      finalExe: fakeExePath,
      sourceVerified: true,
      generationContractHash: "h-e44a337649b66028",
      computedSourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
      quickguiRevision: "0a5007a03be4a0ba08c7da27010f74699711255",
      targetPlatform: "windows",
      targetArch: "x64",
      quickguiToolchain: { verified: true },
      finalPeValidation: { valid: true, sha256: "fake-sha" },
      contractValidation: { valid: true },
      securityPassed: true,
      securityScanResult: { ok: true, findings: [] },
      checkEvidence: { exitCode: 0, durationMs: 100 },
      buildEvidence: { exitCode: 0, durationMs: 100 },
      smokeResult: { passed: true, aliveStatus: true, previewCaptured: true, previewSha256: "fake-preview" },
      runtimeEvidenceResult: {
        status: "PASS",
        manifestSha256: "fake-manifest-sha",
        evidenceCount: 4,
      },
      visualAcceptanceResult: {
        status: "FAIL",
        contractHash: "vac-test",
        reportSha256: "report-sha",
        summary: { total: 40, passed: 30, failed: 10, uncertain: 0 },
      },
    });

    const resFail = buildAcceptanceReport(wsDir);
    expect(resFail.report.accepted).toBe(false);
    expect(resFail.report.status).toBe("visual-failed");
    expect(resFail.report.gateDecisions.visualAcceptance).toBe("fail");

    saveRunResult({
      visualAcceptanceResult: {
        status: "PASS",
        contractHash: "vac-test",
        reportSha256: "report-sha",
        summary: { total: 40, passed: 40, failed: 0, uncertain: 0 },
      },
    });

    const resPass = buildAcceptanceReport(wsDir);
    expect(resPass.report.accepted).toBe(true);
    expect(resPass.report.status).toBe("accepted");
    expect(resPass.report.gateDecisions.visualAcceptance).toBe("pass");
  });

  it("6. buildCallbackPayload embeds visual acceptance fields correctly", () => {
    saveRunResult({
      visualAcceptanceResult: {
        status: "PASS",
        contractHash: "vac-b917446605c0b66d",
        reportSha256: "report-sha-1234",
        summary: { total: 52, totalObligations: 52, passed: 52, failed: 0, uncertain: 0 },
      },
    });

    const payload = buildCallbackPayload("success");
    expect(payload.visual_acceptance_status).toBe("pass");
    expect(payload.visual_acceptance_contract_hash).toBe("vac-b917446605c0b66d");
    expect(payload.visual_acceptance_report_sha256).toBe("report-sha-1234");
    expect(payload.visual_acceptance_obligations_total).toBe(52);
    expect(payload.visual_acceptance_obligations_passed).toBe(52);
    expect(payload.visual_acceptance_obligations_failed).toBe(0);
  });
});
