import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { validatePngHeader, runRuntimeEvidence } from "../scripts/evidence.ts";
import { buildCallbackPayload } from "../scripts/report.ts";
import { buildAcceptanceReport } from "../scripts/generate-acceptance.ts";
import { saveRunResult } from "../scripts/r2.ts";

describe("Decision Harness v0.9C.1 — Windows Runtime Evidence Runner & Negative Matrix", () => {
  const tmpDir = join(import.meta.dir, ".tmp-evidence-test-" + Date.now());
  const wsDir = join(tmpDir, "ws");
  const distDir = join(wsDir, "dist", "windows-x64");
  const fakeExePath = join(distDir, "FinanceTracker.exe");
  const originalEnv = { ...process.env };

  const validPngBytes = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG magic
    0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41,
    0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
    0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
  ]);

  beforeEach(() => {
    mkdirSync(distDir, { recursive: true });
    process.env.RUNNER_TEMP = tmpDir;
    process.env.ADORABLE_JOB_ID = "job_test123";
    process.env.ADORABLE_APP_ID = "com.adorable.financetracker";
    process.env.ADORABLE_BUILD_ID = "build_test123";
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

  it("1. validatePngHeader accepts valid PNG signature and rejects corrupt or truncated headers", () => {
    expect(validatePngHeader(validPngBytes)).toBe(true);
    expect(validatePngHeader(new Uint8Array([]))).toBe(false);
    expect(validatePngHeader(new Uint8Array([0x89, 0x50, 0x4e]))).toBe(false);
    expect(validatePngHeader(new Uint8Array([0x00, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))).toBe(false);
  });

  it("2. Negative A: EXE mutation post-evidence check triggers EVIDENCE_ARTIFACT_MISMATCH fail-closed", async () => {
    saveRunResult({
      wsDir,
      finalExe: fakeExePath,
      generationContractHash: "h-e44a337649b66028",
      computedSourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
      runtimeEvidenceContract: {
        contractVersion: "0.9C.1",
        contractHash: "rec-test1234567890",
        generationContractHash: "h-e44a337649b66028",
        sourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
        targetPlatform: "windows",
        targetArch: "x64",
        quickGuiRevision: "0a5007a03be4a0ba08c7da27010f74699711255",
        expectedScreens: ["dashboard"],
        scenarios: [
          {
            scenarioId: "test-tamper-scenario",
            kind: "STARTUP",
            title: "Tamper test",
            description: "Mutates EXE during scenario execution",
            steps: [
              { stepId: "step-1", action: "WAIT", durationMs: 10 },
            ],
            requiredEvidence: [],
          },
        ],
        evidenceRequirements: [],
      },
    });

    // Mutate the EXE file after initial check starts
    setTimeout(() => {
      writeFileSync(fakeExePath, new Uint8Array([0x4d, 0x5a, 0xff, 0xee, 0xdd, 0xcc]));
    }, 5);

    let errCaught: any = null;
    try {
      await runRuntimeEvidence();
    } catch (err) {
      errCaught = err;
    }

    expect(errCaught).toBeDefined();
    expect(errCaught.code).toBe("EVIDENCE_ARTIFACT_MISMATCH");
  });

  it("3. Negative B: contract mismatch triggers EVIDENCE_CONTRACT_MISMATCH fail-closed", async () => {
    saveRunResult({
      wsDir,
      finalExe: fakeExePath,
      generationContractHash: "h-e44a337649b66028",
      computedSourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
      runtimeEvidenceContract: {
        contractVersion: "0.9C.1",
        contractHash: "rec-test1234567890",
        generationContractHash: "h-tampered-00000000",
        sourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
        targetPlatform: "windows",
        targetArch: "x64",
        quickGuiRevision: "0a5007a03be4a0ba08c7da27010f74699711255",
        expectedScreens: ["dashboard"],
        scenarios: [],
        evidenceRequirements: [],
      },
    });

    let errCaught: any = null;
    try {
      await runRuntimeEvidence();
    } catch (err) {
      errCaught = err;
    }

    expect(errCaught).toBeDefined();
    expect(errCaught.code).toBe("EVIDENCE_CONTRACT_MISMATCH");
  });

  it("4. Negative C: missing screenshot evidence triggers EVIDENCE_MISSING fail-closed", async () => {
    saveRunResult({
      wsDir,
      finalExe: fakeExePath,
      generationContractHash: "h-e44a337649b66028",
      computedSourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
      runtimeEvidenceContract: {
        contractVersion: "0.9C.1",
        contractHash: "rec-test1234567890",
        generationContractHash: "h-e44a337649b66028",
        sourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
        targetPlatform: "windows",
        targetArch: "x64",
        quickGuiRevision: "0a5007a03be4a0ba08c7da27010f74699711255",
        expectedScreens: ["dashboard"],
        scenarios: [
          {
            scenarioId: "test-missing",
            kind: "STARTUP",
            title: "Test Missing",
            description: "Scenario without screenshot step",
            steps: [
              { stepId: "step-wait", action: "WAIT", durationMs: 10 },
            ],
            requiredEvidence: ["req-missing-screenshot"],
          },
        ],
        evidenceRequirements: [
          {
            requirementId: "req-missing-screenshot",
            scenarioId: "test-missing",
            stepId: "step-missing-screenshot",
            type: "screenshot",
            description: "Missing screenshot",
            required: true,
          },
        ],
      },
    });

    let errCaught: any = null;
    try {
      await runRuntimeEvidence();
    } catch (err) {
      errCaught = err;
    }

    expect(errCaught).toBeDefined();
    expect(errCaught.code).toBe("EVIDENCE_MISSING");
  });

  it("5. Callback payload propagation includes runtime evidence status, manifest key, and sha", () => {
    saveRunResult({
      jobId: "job_test123",
      appId: "com.adorable.financetracker",
      buildId: "build_test123",
      generationContractHash: "h-e44a337649b66028",
      computedSourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
      quickguiRevision: "0a5007a03be4a0ba08c7da27010f74699711255",
      runtimeEvidenceManifestKey: "com.adorable.financetracker/build_test123/runtime-evidence/manifest.json",
      runtimeEvidenceManifestSha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      runtimeEvidenceResult: {
        status: "PASS",
        manifestSha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      },
      nativeAcceptanceReport: {
        accepted: true,
        status: "accepted",
        contractHash: "h-e44a337649b66028",
        sourceBundleHash: "3193136f27694a5bfecaa57f38901b294571ad078496b5df54a25c179ea286e1",
        quickguiRevision: "0a5007a03be4a0ba08c7da27010f74699711255",
        gateDecisions: {
          contractValidation: "pass",
          sourceSecurity: "pass",
          quickGuiCheck: "pass",
          quickGuiBuild: "pass",
          launchSmokeTest: "pass",
          runtimeEvidence: "pass",
        },
        blockers: [],
        evidence: [],
        evaluatedAt: new Date().toISOString(),
      },
    });

    const payload = buildCallbackPayload();

    expect(payload.status).toBe("succeeded");
    expect(payload.runtime_evidence_status).toBe("pass");
    expect(payload.runtime_evidence_manifest_key).toBe("com.adorable.financetracker/build_test123/runtime-evidence/manifest.json");
    expect(payload.runtime_evidence_manifest_sha256).toBe("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
  });

  it("6. NativeAcceptanceReport evaluates Gate 6 and sets evidence-failed when evidence status is FAIL", () => {
    saveRunResult({
      wsDir,
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
        status: "FAIL",
        manifestSha256: "fake-manifest-sha",
        evidenceCount: 1,
      },
    });

    const res = buildAcceptanceReport(wsDir);

    expect(res.report.accepted).toBe(false);
    expect(res.report.status).toBe("evidence-failed");
    expect(res.report.gateDecisions.runtimeEvidence).toBe("fail");
    expect(res.report.blockers.some((b) => b.includes("Gate 6"))).toBe(true);
  });
});
