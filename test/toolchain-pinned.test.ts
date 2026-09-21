import { describe, expect, it, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import {
  isMatchingRevision,
  verifyQuickGuiToolchain,
  PINNED_QUICKGUI_REVISION,
  PINNED_QUICKGUI_REVISION_FULL,
  QUICKGUI_REPOSITORY,
} from "../scripts/verify-toolchain.ts";
import {
  setupPinnedToolchain,
  overlayPinnedToolchain,
  ToolchainSetupError,
} from "../scripts/setup-toolchain.ts";
import { resolvePinnedCliCommand } from "../scripts/run-step.ts";
import {
  computeSourceBundleHash,
  type GeneratedFile,
  type SourceBundleProvenanceInputs,
} from "../scripts/source-hash.ts";
import { buildAcceptanceReport } from "../scripts/generate-acceptance.ts";
import { saveRunResult, loadRunResult } from "../scripts/r2.ts";

const TEST_DIR = join(import.meta.dir, ".tmp-toolchain-test-" + Date.now());

function createSyntheticToolchain(dir: string, options?: {
  gitCommit?: string;
  omitDll?: boolean;
  omitCli?: boolean;
  corruptDll?: boolean;
}) {
  mkdirSync(dir, { recursive: true });
  spawnSync("git", ["init"], { cwd: dir, encoding: "utf8" });

  // Init git repo with requested commit
  const commit = options?.gitCommit ?? PINNED_QUICKGUI_REVISION_FULL;
  const refsDir = join(dir, ".git", "refs", "heads");
  mkdirSync(refsDir, { recursive: true });
  writeFileSync(join(refsDir, "main"), `${commit}\n`);
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");

  // CLI entrypoint
  if (!options?.omitCli) {
    const cliSrc = join(dir, "packages", "cli", "src");
    mkdirSync(cliSrc, { recursive: true });
    writeFileSync(join(cliSrc, "cli.ts"), 'console.log("mock quickgui cli");\n');
    const cliPkg = join(dir, "packages", "cli");
    writeFileSync(join(cliPkg, "package.json"), JSON.stringify({ name: "@quickgui/cli", version: "0.1.4-next.4" }));
  }

  // Native host library
  if (!options?.omitDll) {
    const libDir = join(dir, "packages", "native", "lib", "windows-x64");
    mkdirSync(libDir, { recursive: true });
    const dllPath = join(libDir, "quickgui_host.dll");

    if (options?.corruptDll) {
      writeFileSync(dllPath, "corrupt dll content");
    } else {
      // Valid minimal AMD64 PE DLL (> 1MB)
      const size = 1024 * 1024 + 1024;
      const buf = Buffer.alloc(size, 0);
      buf.write("MZ", 0, "ascii");
      const e_lfanew = 0x80;
      buf.writeUInt32LE(e_lfanew, 0x3c);
      buf.write("PE\0\0", e_lfanew, "ascii");
      buf.writeUInt16LE(0x8664, e_lfanew + 4); // AMD64
      buf.writeUInt16LE(1, e_lfanew + 6); // 1 section
      buf.writeUInt16LE(0x020b, e_lfanew + 24); // PE32+ optional header
      const optHeaderSize = 240;
      buf.writeUInt16LE(optHeaderSize, e_lfanew + 20);
      const sectionOffset = e_lfanew + 24 + optHeaderSize;
      buf.write(".text\0\0\0", sectionOffset, "ascii");
      buf.writeUInt32LE(0x1000, sectionOffset + 8);
      buf.writeUInt32LE(0x1000, sectionOffset + 12);
      buf.writeUInt32LE(0x1000, sectionOffset + 16);
      buf.writeUInt32LE(0x1000, sectionOffset + 20);
      writeFileSync(dllPath, buf);
    }

    const nativePkg = join(dir, "packages", "native");
    writeFileSync(join(nativePkg, "package.json"), JSON.stringify({ name: "@quickgui/native", version: "0.1.4-next.4" }));
  }

  // Solid package
  const solidPkg = join(dir, "packages", "solid");
  mkdirSync(solidPkg, { recursive: true });
  writeFileSync(join(solidPkg, "package.json"), JSON.stringify({ name: "@quickgui/solid", version: "0.1.4-next.4" }));
}

describe("Decision Harness v0.9B.2: Source-Pinned QuickGUI Toolchain", () => {
  beforeEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });
    process.env.RUNNER_TEMP = TEST_DIR;
  });

  afterEach(() => {
    delete process.env.RUNNER_TEMP;
    delete process.env.ADORABLE_QUICKGUI_SOURCE_DIR;
    delete process.env.ADORABLE_QUICKGUI_CLI;
    delete process.env.QUICKGUI_LIBRARY;
    delete process.env.ADORABLE_QUICKGUI_VERIFIED_REVISION;
    delete process.env.ADORABLE_QUICKGUI_TOOLCHAIN_EVIDENCE;
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("1. revision validator matches exact pinned SHA and prefix", () => {
    expect(isMatchingRevision(PINNED_QUICKGUI_REVISION)).toBe(true);
    expect(isMatchingRevision(PINNED_QUICKGUI_REVISION_FULL)).toBe(true);
    expect(isMatchingRevision("0a5007a03be4a0ba08c7da27010f74699711255A")).toBe(true);

    // Mismatches
    expect(isMatchingRevision("28d60113dfdf77cb484c20b43bb612b77a16f2c0")).toBe(false);
    expect(isMatchingRevision("0000000000000000000000000000000000000000")).toBe(false);
    expect(isMatchingRevision("")).toBe(false);
    expect(isMatchingRevision(undefined)).toBe(false);
  });

  it("2. verifies healthy pinned toolchain from source repository", () => {
    const toolchainDir = join(TEST_DIR, "pinned-toolchain");
    createSyntheticToolchain(toolchainDir);
    process.env.ADORABLE_QUICKGUI_SOURCE_DIR = toolchainDir;

    const res = verifyQuickGuiToolchain(TEST_DIR);
    expect(res.verified).toBe(true);
    expect(res.verifiedRevision).toBe(PINNED_QUICKGUI_REVISION_FULL);
    expect(res.cliPath).toBe(join(toolchainDir, "packages", "cli", "src", "cli.ts"));
    expect(res.hostLibraryPath).toBe(join(toolchainDir, "packages", "native", "lib", "windows-x64", "quickgui_host.dll"));
    expect(res.buildStatus).toBe("built");
  });

  it("3. rejects toolchain with mismatching git HEAD commit", () => {
    const toolchainDir = join(TEST_DIR, "bad-commit-toolchain");
    createSyntheticToolchain(toolchainDir, {
      gitCommit: "badc0ffee0000000000000000000000000000000",
    });
    process.env.ADORABLE_QUICKGUI_SOURCE_DIR = toolchainDir;

    const res = verifyQuickGuiToolchain(TEST_DIR);
    expect(res.verified).toBe(false);
    expect(res.errorCode).toBe("QUICKGUI_PROVENANCE_UNVERIFIED");
  });

  it("4. rejects toolchain if native host library DLL is missing", () => {
    const toolchainDir = join(TEST_DIR, "missing-dll-toolchain");
    createSyntheticToolchain(toolchainDir, { omitDll: true });
    process.env.ADORABLE_QUICKGUI_SOURCE_DIR = toolchainDir;

    const res = verifyQuickGuiToolchain(TEST_DIR);
    expect(res.verified).toBe(false);
    expect(res.errorCode).toBe("QUICKGUI_PROVENANCE_UNVERIFIED");
  });

  it("5. rejects toolchain if native host library DLL fails PE validation", () => {
    const toolchainDir = join(TEST_DIR, "corrupt-dll-toolchain");
    createSyntheticToolchain(toolchainDir, { corruptDll: true });
    process.env.ADORABLE_QUICKGUI_SOURCE_DIR = toolchainDir;

    const res = verifyQuickGuiToolchain(TEST_DIR);
    expect(res.verified).toBe(false);
    expect(res.errorCode).toBe("QUICKGUI_PROVENANCE_UNVERIFIED");
  });

  it("6. rejects toolchain if CLI entrypoint is missing", () => {
    const toolchainDir = join(TEST_DIR, "missing-cli-toolchain");
    createSyntheticToolchain(toolchainDir, { omitCli: true });
    process.env.ADORABLE_QUICKGUI_SOURCE_DIR = toolchainDir;

    const res = verifyQuickGuiToolchain(TEST_DIR);
    expect(res.verified).toBe(false);
    expect(res.errorCode).toBe("QUICKGUI_PROVENANCE_UNVERIFIED");
  });

  it("7. non-destructive overlay binds @quickgui/* without mutating package.json or app sources", () => {
    const toolchainDir = join(TEST_DIR, "pinned-toolchain");
    createSyntheticToolchain(toolchainDir);

    const appWsDir = join(TEST_DIR, "app-workspace");
    mkdirSync(appWsDir, { recursive: true });
    const originalPkgJson = JSON.stringify({
      name: "com.example.testapp",
      version: "1.0.0",
      dependencies: {
        "@quickgui/native": "0.1.4-next.4",
        "@quickgui/solid": "0.1.4-next.4",
        "@quickgui/cli": "0.1.4-next.4",
        "solid-js": "^1.9.0",
      },
    }, null, 2);
    writeFileSync(join(appWsDir, "package.json"), originalPkgJson, "utf8");

    const appSrcDir = join(appWsDir, "src");
    mkdirSync(appSrcDir, { recursive: true });
    const originalAppCode = 'import { Window } from "@quickgui/solid"; export default () => <Window />;\n';
    writeFileSync(join(appSrcDir, "index.tsx"), originalAppCode, "utf8");

    // Compute source bundle hash BEFORE overlay
    const files: GeneratedFile[] = [
      { path: "package.json", content: originalPkgJson },
      { path: "src/index.tsx", content: originalAppCode },
    ];
    const prov: SourceBundleProvenanceInputs = {
      generationContractHash: "h-0123456789abcdef",
      generationContractVersion: "1.0.0",
      quickGuiRepository: QUICKGUI_REPOSITORY,
      quickGuiRevision: PINNED_QUICKGUI_REVISION,
      targetPlatform: "windows",
      targetArch: "x64",
    };

    const hashBeforeOverlay = computeSourceBundleHash(files, prov);

    // Apply overlay
    overlayPinnedToolchain(appWsDir, toolchainDir);

    // Verify overlay exists in node_modules/@quickgui
    expect(existsSync(join(appWsDir, "node_modules", "@quickgui", "cli"))).toBe(true);
    expect(existsSync(join(appWsDir, "node_modules", "@quickgui", "native"))).toBe(true);
    expect(existsSync(join(appWsDir, "node_modules", "@quickgui", "solid"))).toBe(true);

    // Invariant: package.json and src/index.tsx must NOT be modified
    const currentPkgJson = readFileSync(join(appWsDir, "package.json"), "utf8");
    const currentAppCode = readFileSync(join(appWsDir, "src", "index.tsx"), "utf8");
    expect(currentPkgJson).toBe(originalPkgJson);
    expect(currentAppCode).toBe(originalAppCode);

    // Invariant: computeSourceBundleHash must remain 100% identical
    const filesAfter: GeneratedFile[] = [
      { path: "package.json", content: currentPkgJson },
      { path: "src/index.tsx", content: currentAppCode },
    ];
    const hashAfterOverlay = computeSourceBundleHash(filesAfter, prov);
    expect(hashAfterOverlay).toBe(hashBeforeOverlay);
  });

  it("8. resolvePinnedCliCommand resolves pinned CLI entrypoint and sets QUICKGUI_LIBRARY", () => {
    const toolchainDir = join(TEST_DIR, "pinned-toolchain");
    createSyntheticToolchain(toolchainDir);
    process.env.ADORABLE_QUICKGUI_SOURCE_DIR = toolchainDir;

    const resolved = resolvePinnedCliCommand("check");
    expect(resolved.cmd[0]).toBe("bun");
    expect(resolved.cmd[1]).toBe(join(toolchainDir, "packages", "cli", "src", "cli.ts"));
    expect(resolved.cmd[2]).toBe("check");
    expect(resolved.extraEnv.QUICKGUI_LIBRARY).toBe(
      join(toolchainDir, "packages", "native", "lib", "windows-x64", "quickgui_host.dll"),
    );
  });

  it("9. resolvePinnedCliCommand fails closed when pinned CLI cannot be found", () => {
    delete process.env.ADORABLE_QUICKGUI_SOURCE_DIR;
    delete process.env.ADORABLE_QUICKGUI_CLI;
    saveRunResult({ pinnedToolchainDir: undefined, pinnedCliEntrypoint: undefined, pinnedHostLibrary: undefined });

    expect(() => {
      resolvePinnedCliCommand("check");
    }).toThrow();
  });

  it("10. NativeAcceptanceReport and NativeGenerationResult record toolchain provenance", () => {
    const toolchainDir = join(TEST_DIR, "pinned-toolchain");
    createSyntheticToolchain(toolchainDir);
    process.env.ADORABLE_QUICKGUI_SOURCE_DIR = toolchainDir;

    const wsDir = join(TEST_DIR, "ws");
    mkdirSync(wsDir, { recursive: true });

    saveRunResult({
      wsDir,
      generationContractHash: "h-0123456789abcdef",
      computedSourceBundleHash: "a".repeat(64),
      quickguiRevision: PINNED_QUICKGUI_REVISION,
      targetPlatform: "windows",
      targetArch: "x64",
      sourceVerified: true,
      securityPassed: true,
      securityScanResult: { ok: true, findings: [] },
      quickguiToolchain: {
        verified: true,
        repository: QUICKGUI_REPOSITORY,
        expectedRevision: PINNED_QUICKGUI_REVISION,
        verifiedRevision: PINNED_QUICKGUI_REVISION_FULL,
        cliPath: join(toolchainDir, "packages", "cli", "src", "cli.ts"),
        hostLibraryPath: join(toolchainDir, "packages", "native", "lib", "windows-x64", "quickgui_host.dll"),
        buildStatus: "built",
      },
      checkEvidence: {
        command: `bun ${join(toolchainDir, "packages", "cli", "src", "cli.ts")} check`,
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 50,
        exitCode: 0,
        stdout: "All checks passed",
        stderr: "",
      },
      buildEvidence: {
        command: `bun ${join(toolchainDir, "packages", "cli", "src", "cli.ts")} build`,
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 100,
        exitCode: 0,
        stdout: "Build succeeded",
        stderr: "",
      },
      finalPeValidation: {
        valid: true,
        sha256: "b".repeat(64),
        size: 2000000,
        machine: "IMAGE_FILE_MACHINE_AMD64 (0x8664)",
      },
      smokeResult: {
        passed: true,
        aliveStatus: true,
        previewCaptured: true,
        previewSha256: "c".repeat(64),
      },
    });

    const { report, generationResult } = buildAcceptanceReport(wsDir);

    expect(report.accepted).toBe(true);
    expect(report.status).toBe("accepted");
    expect(report.toolchain?.verifiedRevision).toBe(PINNED_QUICKGUI_REVISION_FULL);
    expect(report.toolchain?.repository).toBe(QUICKGUI_REPOSITORY);
    expect(report.toolchain?.buildStatus).toBe("built");

    expect(generationResult.toolchain?.verifiedRevision).toBe(PINNED_QUICKGUI_REVISION_FULL);
    expect(generationResult.finalStatus).toBe("accepted");
  });
});
