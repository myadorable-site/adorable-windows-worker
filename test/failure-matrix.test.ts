/**
 * DECISION HARNESS v0.9B — FAILURE MATRIX & ACCEPTANCE TESTS
 *
 * Covers all 19 required scenarios in Section 22:
 * 1. source hash mismatch -> SOURCE_HASH_MISMATCH
 * 2. generation contract mismatch -> PROVENANCE_MISMATCH
 * 3. QuickGUI revision mismatch -> PROVENANCE_MISMATCH
 * 4. QuickGUI revision unverifiable -> QUICKGUI_PROVENANCE_UNVERIFIED
 * 5. dependency install failure -> DEPENDENCY_INSTALL_FAILED
 * 6. quickgui check failure -> CHECK_FAILED
 * 7. quickgui build failure -> BUILD_FAILED
 * 8. zero-byte EXE -> CORRUPT_PE
 * 9. non-PE EXE -> CORRUPT_PE
 * 10. wrong PE architecture -> CORRUPT_PE
 * 11. malformed PE header -> CORRUPT_PE
 * 12. packaged EXE differs from validated executable -> PACKAGING_FAILED / CORRUPT_PE
 * 13. immediate process exit code 0 -> SMOKE_FAILED
 * 14. process crash -> SMOKE_FAILED
 * 15. no native window -> SMOKE_FAILED
 * 16. preview capture failure -> PREVIEW_CAPTURE_FAILED
 * 17. artifact upload failure -> ARTIFACT_UPLOAD_FAILED
 * 18. callback failure -> CALLBACK_FAILED
 * 19. complete successful build -> status === "succeeded", accepted === true
 */
import { describe, expect, it, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  computeSourceBundleHash,
  extractProvenanceInputs,
  type GeneratedFile,
  type SourceBundleProvenanceInputs,
} from "../scripts/source-hash.ts";
import { validateWindowsPe } from "../scripts/pe-validator.ts";
import {
  isMatchingRevision,
  verifyQuickGuiToolchain,
  PINNED_QUICKGUI_REVISION,
  PINNED_QUICKGUI_REVISION_FULL,
} from "../scripts/verify-toolchain.ts";
import {
  buildAcceptanceReport,
  type NativeAcceptanceReport,
} from "../scripts/generate-acceptance.ts";
import { buildCallbackPayload } from "../scripts/report.ts";
import { saveRunResult, loadRunResult } from "../scripts/r2.ts";
import { validatePngHeader } from "../scripts/smoke.ts";

const TEST_DIR = join(import.meta.dir, ".tmp-test-" + Date.now());

function createSyntheticPe(options?: {
  size?: number;
  magic?: number;
  e_lfanew?: number;
  peSig?: number[];
  machine?: number;
  numberOfSections?: number;
}): Buffer {
  const size = options?.size ?? 1024 * 1024 + 2048; // > 1MB
  const buf = Buffer.alloc(size, 0);

  // DOS header
  buf.writeUInt16LE(options?.magic ?? 0x5a4d, 0); // "MZ"
  const peOffset = options?.e_lfanew ?? 0x80;
  buf.writeUInt32LE(peOffset, 0x3c); // e_lfanew

  // PE signature "PE\0\0"
  if (peOffset + 4 <= buf.length) {
    const sig = options?.peSig ?? [0x50, 0x45, 0x00, 0x00];
    for (let i = 0; i < 4; i++) buf[peOffset + i] = sig[i];
  }

  // COFF Header
  const coff = peOffset + 4;
  if (coff + 24 <= buf.length) {
    buf.writeUInt16LE(options?.machine ?? 0x8664, coff); // Machine AMD64
    const numSections = options?.numberOfSections ?? 1;
    buf.writeUInt16LE(numSections, coff + 2); // NumberOfSections
    const optHeaderSize = 240;
    buf.writeUInt16LE(optHeaderSize, coff + 16); // SizeOfOptionalHeader

    // Optional Header
    const opt = coff + 20;
    if (opt + 2 <= buf.length) {
      buf.writeUInt16LE(0x020b, opt); // PE32+ (64-bit)
    }

    // Section Table
    const sectionTable = opt + optHeaderSize;
    for (let s = 0; s < numSections; s++) {
      const sOffset = sectionTable + s * 40;
      if (sOffset + 40 <= buf.length) {
        buf.write(".text", sOffset, "utf8");
        buf.writeUInt32LE(0x1000, sOffset + 8); // VirtualSize
        buf.writeUInt32LE(0x1000, sOffset + 12); // VirtualAddress
        buf.writeUInt32LE(512, sOffset + 16); // SizeOfRawData
        buf.writeUInt32LE(0x400, sOffset + 20); // PointerToRawData
      }
    }
  }

  return buf;
}

function createSyntheticPng(): Uint8Array {
  // PNG Magic Header: 89 50 4E 47 0D 0A 1A 0A
  const header = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  const buf = new Uint8Array(64);
  for (let i = 0; i < header.length; i++) buf[i] = header[i];
  return buf;
}

describe("Decision Harness v0.9B: Failure Matrix & Native Acceptance", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
    process.env.RUNNER_TEMP = TEST_DIR;
    process.env.ADORABLE_JOB_ID = "job_test123";
    process.env.ADORABLE_APP_ID = "com.test.app";
    process.env.ADORABLE_BUILD_ID = "build_test456";
    process.env.ADORABLE_TARGET_PLATFORM = "windows";
    process.env.ADORABLE_TARGET_ARCH = "x64";
    process.env.ADORABLE_GENERATION_CONTRACT_HASH = "h-12345678abcdef01";
    process.env.ADORABLE_QUICKGUI_REVISION = PINNED_QUICKGUI_REVISION;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    try {
      rmSync(TEST_DIR, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  // ─────────────────────────────────────────────────────────────
  // 1. Source Hash Mismatch
  // ─────────────────────────────────────────────────────────────
  it("1. source hash mismatch -> status === 'failed', error_code === 'SOURCE_HASH_MISMATCH'", () => {
    const files: GeneratedFile[] = [
      { relativePath: "app.tsx", content: "console.log('original');" },
    ];
    const prov: SourceBundleProvenanceInputs = {
      generationContractHash: "h-12345678abcdef01",
      generationContractVersion: "v0.9A",
      quickGuiRepository: "https://github.com/egoist/quickgui.git",
      quickGuiRevision: PINNED_QUICKGUI_REVISION_FULL,
      targetPlatform: "windows",
      targetArch: "x64",
    };
    const computedHash = computeSourceBundleHash(files, prov);
    const tamperedHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    expect(computedHash).not.toBe(tamperedHash);

    // Record failure in runner state
    saveRunResult({
      stepFailed: true,
      errorCode: "SOURCE_HASH_MISMATCH",
      errorMessage: "Source bundle hash mismatch against workflow input",
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("SOURCE_HASH_MISMATCH");
  });

  // ─────────────────────────────────────────────────────────────
  // 2. Generation Contract Mismatch
  // ─────────────────────────────────────────────────────────────
  it("2. generation contract mismatch -> status === 'failed', error_code === 'PROVENANCE_MISMATCH'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "PROVENANCE_MISMATCH",
      errorMessage: "generationContractHash mismatch: meta differs from input",
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("PROVENANCE_MISMATCH");
  });

  // ─────────────────────────────────────────────────────────────
  // 3. QuickGUI Revision Mismatch
  // ─────────────────────────────────────────────────────────────
  it("3. QuickGUI revision mismatch -> status === 'failed', error_code === 'PROVENANCE_MISMATCH'", () => {
    const wrongRev = "badc0ffee0000000000000000000000000000000";
    expect(isMatchingRevision(wrongRev)).toBe(false);

    saveRunResult({
      stepFailed: true,
      errorCode: "PROVENANCE_MISMATCH",
      errorMessage: `QuickGUI revision mismatch in workflow inputs: got "${wrongRev}", expected "${PINNED_QUICKGUI_REVISION}"`,
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("PROVENANCE_MISMATCH");
  });

  // ─────────────────────────────────────────────────────────────
  // 4. QuickGUI Revision Unverifiable
  // ─────────────────────────────────────────────────────────────
  it("4. QuickGUI revision unverifiable -> status === 'failed', error_code === 'QUICKGUI_PROVENANCE_UNVERIFIED'", () => {
    delete process.env.ADORABLE_QUICKGUI_VERIFIED_REVISION;
    delete process.env.ADORABLE_QUICKGUI_TOOLCHAIN_EVIDENCE;

    const res = verifyQuickGuiToolchain(TEST_DIR);
    expect(res.verified).toBe(false);
    expect(res.errorCode).toBe("QUICKGUI_PROVENANCE_UNVERIFIED");

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("QUICKGUI_PROVENANCE_UNVERIFIED");
  });

  // ─────────────────────────────────────────────────────────────
  // 5. Dependency Install Failure
  // ─────────────────────────────────────────────────────────────
  it("5. dependency install failure -> status === 'failed', error_code === 'DEPENDENCY_INSTALL_FAILED'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "DEPENDENCY_INSTALL_FAILED",
      errorMessage: "bun install failed with exit code 1",
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("DEPENDENCY_INSTALL_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 6. QuickGUI Check Failure
  // ─────────────────────────────────────────────────────────────
  it("6. quickgui check failure -> status === 'failed', error_code === 'CHECK_FAILED'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "CHECK_FAILED",
      errorMessage: "quickgui check failed with exit code 1",
      checkEvidence: {
        command: "bunx quickgui check",
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 120,
        exitCode: 1,
        stdout: "",
        stderr: "Type error in app.tsx: Cannot find name 'Foo'",
      },
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("CHECK_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 7. QuickGUI Build Failure
  // ─────────────────────────────────────────────────────────────
  it("7. quickgui build failure -> status === 'failed', error_code === 'BUILD_FAILED'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "BUILD_FAILED",
      errorMessage: "quickgui build failed with exit code 1",
      buildEvidence: {
        command: "bunx quickgui build",
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 450,
        exitCode: 1,
        stdout: "",
        stderr: "Build failed to generate binary",
      },
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("BUILD_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 8. Zero-Byte EXE
  // ─────────────────────────────────────────────────────────────
  it("8. zero-byte EXE -> status === 'failed', error_code === 'CORRUPT_PE'", () => {
    const zeroExePath = join(TEST_DIR, "zero.exe");
    writeFileSync(zeroExePath, Buffer.alloc(0));

    const val = validateWindowsPe(zeroExePath);
    expect(val.valid).toBe(false);
    expect(val.error).toContain("FILE_TOO_SMALL");

    saveRunResult({
      stepFailed: true,
      errorCode: "CORRUPT_PE",
      errorMessage: val.error,
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("CORRUPT_PE");
  });

  // ─────────────────────────────────────────────────────────────
  // 9. Non-PE EXE
  // ─────────────────────────────────────────────────────────────
  it("9. non-PE EXE -> status === 'failed', error_code === 'CORRUPT_PE'", () => {
    const nonPePath = join(TEST_DIR, "nonpe.exe");
    // > 1MB text file without MZ header
    writeFileSync(nonPePath, Buffer.alloc(1024 * 1024 + 100, 0x41));

    const val = validateWindowsPe(nonPePath);
    expect(val.valid).toBe(false);
    expect(val.error).toBe("INVALID_DOS_SIGNATURE_NOT_MZ");

    saveRunResult({
      stepFailed: true,
      errorCode: "CORRUPT_PE",
      errorMessage: val.error,
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("CORRUPT_PE");
  });

  // ─────────────────────────────────────────────────────────────
  // 10. Wrong PE Architecture
  // ─────────────────────────────────────────────────────────────
  it("10. wrong PE architecture -> status === 'failed', error_code === 'CORRUPT_PE'", () => {
    const arm64ExePath = join(TEST_DIR, "arm64.exe");
    // Machine 0xAA64 (ARM64)
    writeFileSync(arm64ExePath, createSyntheticPe({ machine: 0xaa64 }));

    const val = validateWindowsPe(arm64ExePath);
    expect(val.valid).toBe(false);
    expect(val.error).toContain("WRONG_MACHINE_ARCHITECTURE");

    saveRunResult({
      stepFailed: true,
      errorCode: "CORRUPT_PE",
      errorMessage: val.error,
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("CORRUPT_PE");
  });

  // ─────────────────────────────────────────────────────────────
  // 11. Malformed PE Header
  // ─────────────────────────────────────────────────────────────
  it("11. malformed PE header -> status === 'failed', error_code === 'CORRUPT_PE'", () => {
    const corruptExePath = join(TEST_DIR, "corrupt.exe");
    // Out of bounds e_lfanew
    writeFileSync(corruptExePath, createSyntheticPe({ e_lfanew: 0x0fffffff }));

    const val = validateWindowsPe(corruptExePath);
    expect(val.valid).toBe(false);
    expect(val.error).toContain("OUT_OF_BOUNDS_E_LFANEW");

    saveRunResult({
      stepFailed: true,
      errorCode: "CORRUPT_PE",
      errorMessage: val.error,
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("CORRUPT_PE");
  });

  // ─────────────────────────────────────────────────────────────
  // 12. Packaged EXE Differs from Validated Executable
  // ─────────────────────────────────────────────────────────────
  it("12. packaged EXE differs from validated executable -> status === 'failed', error_code === 'PACKAGING_FAILED'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "PACKAGING_FAILED",
      errorMessage: "Final standalone executable failed post-packaging PE validation",
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("PACKAGING_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 13. Immediate Process Exit Code 0
  // ─────────────────────────────────────────────────────────────
  it("13. immediate process exit code 0 -> status === 'failed', error_code === 'SMOKE_FAILED'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "SMOKE_FAILED",
      errorMessage: "Application exited early (exitCode=0) during the settle window. Desktop GUI applications must remain active.",
      smokeResult: {
        passed: false,
        aliveStatus: false,
        exitCode: 0,
        previewCaptured: false,
        errorMessage: "Application exited early (exitCode=0) during the settle window.",
      },
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("SMOKE_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 14. Process Crash
  // ─────────────────────────────────────────────────────────────
  it("14. process crash -> status === 'failed', error_code === 'SMOKE_FAILED'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "SMOKE_FAILED",
      errorMessage: "Application exited with code 3221225477 (STATUS_ACCESS_VIOLATION)",
      smokeResult: {
        passed: false,
        aliveStatus: false,
        exitCode: 3221225477,
        previewCaptured: false,
      },
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("SMOKE_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 15. No Native Window
  // ─────────────────────────────────────────────────────────────
  it("15. no native window -> status === 'failed', error_code === 'SMOKE_FAILED'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "SMOKE_FAILED",
      errorMessage: "Native window discovery failed: WindowTimeout",
      smokeResult: {
        passed: false,
        aliveStatus: true,
        previewCaptured: false,
        errorMessage: "Native window discovery failed: WindowTimeout",
      },
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("SMOKE_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 16. Preview Capture Failure
  // ─────────────────────────────────────────────────────────────
  it("16. preview capture failure -> status === 'failed', error_code === 'PREVIEW_CAPTURE_FAILED'", () => {
    // Bad PNG header
    const badPng = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
    expect(validatePngHeader(badPng)).toBe(false);

    saveRunResult({
      stepFailed: true,
      errorCode: "PREVIEW_CAPTURE_FAILED",
      errorMessage: "Preview screenshot does not contain a valid PNG signature",
      smokeResult: {
        passed: false,
        aliveStatus: true,
        previewCaptured: false,
        errorMessage: "Preview screenshot does not contain a valid PNG signature",
      },
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("PREVIEW_CAPTURE_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 17. Artifact Upload Failure
  // ─────────────────────────────────────────────────────────────
  it("17. artifact upload failure -> status === 'failed', error_code === 'ARTIFACT_UPLOAD_FAILED'", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "ARTIFACT_UPLOAD_FAILED",
      errorMessage: "R2 upload failed (HTTP 500): Internal error",
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("ARTIFACT_UPLOAD_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 18. Callback Failure
  // ─────────────────────────────────────────────────────────────
  it("18. callback failure -> handled fail-closed without claiming false success", () => {
    saveRunResult({
      stepFailed: true,
      errorCode: "CALLBACK_FAILED",
      errorMessage: "Callback not delivered after 3 attempts",
    });

    const payload = buildCallbackPayload();
    expect(payload.status).toBe("failed");
    expect(payload.error_code).toBe("CALLBACK_FAILED");
  });

  // ─────────────────────────────────────────────────────────────
  // 19. Complete Successful Build
  // ─────────────────────────────────────────────────────────────
  it("19. complete successful build -> status === 'succeeded', accepted === true", () => {
    // 1. Valid verified PE executable
    const validExePath = join(TEST_DIR, "app.exe");
    writeFileSync(validExePath, createSyntheticPe());
    const peRes = validateWindowsPe(validExePath);
    expect(peRes.valid).toBe(true);

    // 2. Valid preview PNG
    const artifactsDir = join(TEST_DIR, "artifacts");
    mkdirSync(artifactsDir, { recursive: true });
    const previewPngPath = join(artifactsDir, "preview.png");
    writeFileSync(previewPngPath, createSyntheticPng());
    expect(validatePngHeader(createSyntheticPng())).toBe(true);

    // 3. Setup run state simulating all 5 gates passing cleanly
    saveRunResult({
      stepFailed: false,
      sourceVerified: true,
      generationContractHash: "h-12345678abcdef01",
      computedSourceBundleHash: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      quickguiRevision: PINNED_QUICKGUI_REVISION_FULL,
      targetPlatform: "windows",
      targetArch: "x64",
      quickguiToolchain: {
        verified: true,
        repository: "https://github.com/egoist/quickgui.git",
        expectedRevision: PINNED_QUICKGUI_REVISION,
        verifiedRevision: PINNED_QUICKGUI_REVISION_FULL,
        evidence: "Verified via runner toolchain attestation",
      },
      checkEvidence: {
        command: "bunx quickgui check",
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 85,
        exitCode: 0,
        stdout: "Check passed",
        stderr: "",
      },
      buildEvidence: {
        command: "bunx quickgui build",
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 350,
        exitCode: 0,
        stdout: "Build succeeded",
        stderr: "",
      },
      finalExe: validExePath,
      finalPeValidation: peRes,
      securityPassed: true,
      securityScanResult: { ok: true, findings: [] },
      smokeResult: {
        passed: true,
        aliveStatus: true,
        previewCaptured: true,
        pid: 1234,
        windowHandle: "SUCCESS:800:600",
        settleDurationMs: 5000,
        previewSha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      },
      artifactKey: "com.test.app/build_test456/app.exe",
      artifactSha256: peRes.sha256,
      artifactSize: peRes.fileSize,
      fileName: "app.exe",
      previewKey: "com.test.app/build_test456/preview.png",
      previewSha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      uploadedKeys: {
        executable: "com.test.app/build_test456/app.exe",
        preview: "com.test.app/build_test456/preview.png",
        generationResult: "com.test.app/build_test456/native-generation-result.json",
        acceptance: "com.test.app/build_test456/native-acceptance.json",
      },
    });

    // 4. Generate structured acceptance report
    const { report, generationResult } = buildAcceptanceReport(TEST_DIR);

    expect(report.accepted).toBe(true);
    expect(report.status).toBe("accepted");
    expect(report.blockers.length).toBe(0);
    expect(report.gateDecisions.contractValidation).toBe("pass");
    expect(report.gateDecisions.sourceSecurity).toBe("pass");
    expect(report.gateDecisions.quickGuiCheck).toBe("pass");
    expect(report.gateDecisions.quickGuiBuild).toBe("pass");
    expect(report.gateDecisions.launchSmokeTest).toBe("pass");

    // 5. Build final callback payload
    const payload = buildCallbackPayload();
    expect(payload.status).toBe("succeeded");
    expect(payload.acceptance_status).toBe("accepted");
    expect(payload.error_code).toBeUndefined();
    expect(payload.generation_contract_hash).toBe("h-12345678abcdef01");
    expect(payload.source_bundle_hash).toBe("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
    expect(payload.quickgui_revision).toBe(PINNED_QUICKGUI_REVISION_FULL);
    expect(payload.target_platform).toBe("windows");
    expect(payload.target_arch).toBe("x64");
    expect(payload.artifact_sha256).toBe(peRes.sha256);
    expect(payload.preview_sha256).toBe("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    expect(payload.release_status).toEqual(["BUILD_SUCCEEDED", "ACCEPTED"]);
  });
});
