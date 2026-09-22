/**
 * Stage and build the pinned QuickGUI toolchain from source.
 *
 * Requirements:
 * - Git repository: https://github.com/egoist/quickgui.git
 * - Exact pinned revision: 0a5007a03be4a0ba08c7da27010f74699711255
 * - Exact Git commit verification via git rev-parse HEAD
 * - Zero app mutation invariant: apps do not change package.json
 * - Build QuickGUI native host library (quickgui_host.dll) & verify AMD64 PE
 * - Non-destructively overlay @quickgui/* into app node_modules/@quickgui
 */
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { loadRunResult, saveRunResult } from "./r2.ts";
import { validateWindowsPe } from "./pe-validator.ts";
import {
  isMatchingRevision,
  PINNED_QUICKGUI_REVISION,
  PINNED_QUICKGUI_REVISION_FULL,
  QUICKGUI_REPOSITORY,
  type ToolchainVerificationResult,
} from "./verify-toolchain.ts";

export interface SetupToolchainOptions {
  sourceDir?: string;
  skipBuild?: boolean;
}

export interface StagedToolchain {
  toolchainDir: string;
  gitCommit: string;
  cliEntrypoint: string;
  hostLibraryPath: string;
  verified: boolean;
}

export class ToolchainSetupError extends Error {
  code = "QUICKGUI_PROVENANCE_UNVERIFIED";
  constructor(message: string) {
    super(message);
    this.name = "ToolchainSetupError";
  }
}

/**
 * Locates Microsoft Manifest Tool (mt.exe) from PATH or standard Windows Kits directories.
 */
export function findMtExe(): string | null {
  try {
    const res = spawnSync("where.exe", ["mt.exe"], { encoding: "utf8" });
    if (res.status === 0 && res.stdout) {
      const p = res.stdout.split(/\r?\n/)[0].trim();
      if (p && existsSync(p)) return p;
    }
  } catch {
    /* ignore */
  }

  const kitsBase = "C:\\Program Files (x86)\\Windows Kits\\10\\bin";
  if (existsSync(kitsBase)) {
    try {
      const versions = readdirSync(kitsBase);
      versions.sort().reverse();
      for (const ver of versions) {
        const mtCand = join(kitsBase, ver, "x64", "mt.exe");
        if (existsSync(mtCand)) return mtCand;
      }
    } catch {
      /* ignore */
    }
  }
  return null;
}

/**
 * Embeds Common-Controls v6 manifest into quickgui_host.dll as RT_MANIFEST resource #2.
 * Required on Windows because rfd imports TaskDialogIndirect from comctl32.dll,
 * which is only exported by ComCtl32 v6.0+. Without this manifest, Windows resolves
 * comctl32.dll to legacy v5.82 and fails with Win32 Error 127 (ERROR_PROC_NOT_FOUND).
 */
export function embedCommonControlsManifest(dllPath: string): boolean {
  const mtExe = findMtExe();
  if (!mtExe) {
    console.warn("[Toolchain Setup] Warning: mt.exe not found, skipping manifest embedding.");
    return false;
  }

  const manifestXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="QuickGUI.Host" type="win32"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
`;
  const tmpManifest = join(dirname(dllPath), `.manifest-${Date.now()}.xml`);
  writeFileSync(tmpManifest, manifestXml, "utf8");

  try {
    console.log(`[Toolchain Setup] Embedding Common-Controls v6 manifest into ${dllPath}...`);
    const res = spawnSync(mtExe, ["-manifest", tmpManifest, `-outputresource:${dllPath};#2`], {
      encoding: "utf8",
    });
    if (res.status === 0) {
      console.log(`[Toolchain Setup] Successfully embedded Common-Controls v6 manifest into ${dllPath}`);
      return true;
    } else {
      console.warn(`[Toolchain Setup] mt.exe exited with status ${res.status}: ${res.stderr || res.stdout}`);
      return false;
    }
  } finally {
    try {
      unlinkSync(tmpManifest);
    } catch {
      /* ignore */
    }
  }
}

/**
 * Resolves or stages the pinned QuickGUI toolchain from git source.
 */
export function setupPinnedToolchain(options?: SetupToolchainOptions): StagedToolchain {
  console.log(`[Toolchain Setup] Target repository: ${QUICKGUI_REPOSITORY}`);
  console.log(`[Toolchain Setup] Required revision: ${PINNED_QUICKGUI_REVISION}`);

  // Determine toolchain source directory
  let toolchainDir =
    options?.sourceDir ??
    process.env.ADORABLE_QUICKGUI_SOURCE_DIR ??
    (process.env.RUNNER_TEMP ? join(process.env.RUNNER_TEMP, "quickgui-pinned") : "");

  if (!toolchainDir) {
    // If local checkout exists (development machine), use it
    const localDevPath = resolve("D:\\adorable\\quickgui-upstream");
    if (existsSync(localDevPath)) {
      toolchainDir = localDevPath;
    } else {
      toolchainDir = join(tmpdir(), "adorable-quickgui-pinned");
    }
  }

  toolchainDir = resolve(toolchainDir);
  console.log(`[Toolchain Setup] Using toolchain directory: ${toolchainDir}`);

  // 1. Clone or verify checkout
  if (!existsSync(toolchainDir)) {
    console.log(`[Toolchain Setup] Cloning ${QUICKGUI_REPOSITORY} into ${toolchainDir}...`);
    mkdirSync(toolchainDir, { recursive: true });
    const cloneRes = spawnSync(
      "git",
      ["clone", "--no-checkout", QUICKGUI_REPOSITORY, toolchainDir],
      { encoding: "utf8", stdio: "inherit" },
    );
    if (cloneRes.status !== 0) {
      throw new ToolchainSetupError(`Failed to clone QuickGUI repository: exit code ${cloneRes.status}`);
    }
  }

  // 2. Checkout exact pinned commit
  console.log(`[Toolchain Setup] Checking out commit ${PINNED_QUICKGUI_REVISION}...`);
  const checkoutRes = spawnSync(
    "git",
    ["checkout", PINNED_QUICKGUI_REVISION],
    { cwd: toolchainDir, encoding: "utf8", stdio: "inherit" },
  );
  if (checkoutRes.status !== 0) {
    // Attempt fetch in case commit is not local
    console.log("[Toolchain Setup] Fetching from origin...");
    spawnSync("git", ["fetch", "origin", PINNED_QUICKGUI_REVISION], {
      cwd: toolchainDir,
      encoding: "utf8",
      stdio: "inherit",
    });
    const retryCheckout = spawnSync(
      "git",
      ["checkout", PINNED_QUICKGUI_REVISION],
      { cwd: toolchainDir, encoding: "utf8", stdio: "inherit" },
    );
    if (retryCheckout.status !== 0) {
      throw new ToolchainSetupError(
        `Failed to checkout pinned QuickGUI revision ${PINNED_QUICKGUI_REVISION}`,
      );
    }
  }

  // 3. Cryptographically verify git rev-parse HEAD
  const revParse = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: toolchainDir,
    encoding: "utf8",
  });
  if (revParse.status !== 0) {
    throw new ToolchainSetupError(
      `Failed to determine QuickGUI HEAD commit: ${revParse.stderr || "git rev-parse failed"}`,
    );
  }

  const headCommit = (revParse.stdout || "").trim();
  console.log(`[Toolchain Setup] Verified HEAD commit: ${headCommit}`);

  if (!isMatchingRevision(headCommit)) {
    throw new ToolchainSetupError(
      `QuickGUI git HEAD (${headCommit}) does not match pinned revision ${PINNED_QUICKGUI_REVISION}`,
    );
  }

  // 4. Install toolchain dependencies with frozen lockfile
  if (!options?.skipBuild) {
    console.log("[Toolchain Setup] Installing QuickGUI toolchain dependencies (bun install --frozen-lockfile)...");
    const installRes = spawnSync("bun", ["install", "--frozen-lockfile"], {
      cwd: toolchainDir,
      encoding: "utf8",
      stdio: "inherit",
    });
    if (installRes.status !== 0) {
      throw new ToolchainSetupError(`Failed to install QuickGUI dependencies: exit code ${installRes.status}`);
    }
  }

  // 5. Verify / compile native host shared library (quickgui_host.dll)
  const hostDllPath = join(
    toolchainDir,
    "packages",
    "native",
    "lib",
    "windows-x64",
    "quickgui_host.dll",
  );
  const releaseDllPath = join(toolchainDir, "target", "release", "quickgui_host.dll");

  let dllExists = existsSync(hostDllPath);

  if (!dllExists && existsSync(releaseDllPath)) {
    mkdirSync(join(toolchainDir, "packages", "native", "lib", "windows-x64"), { recursive: true });
    cpSync(releaseDllPath, hostDllPath);
    dllExists = true;
  }

  if (!dllExists && !options?.skipBuild) {
    console.log("[Toolchain Setup] Compiling QuickGUI native host library (quickgui_host.dll)...");
    const nativeBuildRes = spawnSync("bun", ["packages/native/build.ts"], {
      cwd: toolchainDir,
      encoding: "utf8",
      stdio: "inherit",
      env: { ...process.env },
    });
    if (nativeBuildRes.status !== 0) {
      // Fallback: try direct cargo build
      console.log("[Toolchain Setup] Trying cargo build -p quickgui-host --lib --release...");
      const cargoRes = spawnSync(
        "cargo",
        ["build", "-p", "quickgui-host", "--lib", "--release"],
        { cwd: toolchainDir, encoding: "utf8", stdio: "inherit", env: { ...process.env } },
      );
      if (cargoRes.status !== 0) {
        throw new ToolchainSetupError("Failed to build quickgui-host native library via Cargo.");
      }
      if (existsSync(releaseDllPath)) {
        mkdirSync(join(toolchainDir, "packages", "native", "lib", "windows-x64"), { recursive: true });
        cpSync(releaseDllPath, hostDllPath);
      }
    }
  }

  const finalDllPath = existsSync(hostDllPath) ? hostDllPath : releaseDllPath;
  if (!existsSync(finalDllPath)) {
    throw new ToolchainSetupError(
      `QuickGUI native host library not found at ${hostDllPath} or ${releaseDllPath}`,
    );
  }

  // Embed Common-Controls v6 manifest into quickgui_host.dll if mt.exe is available
  embedCommonControlsManifest(finalDllPath);
  if (existsSync(releaseDllPath) && releaseDllPath !== finalDllPath) {
    embedCommonControlsManifest(releaseDllPath);
  }

  // Verify PE integrity of quickgui_host.dll
  const peCheck = validateWindowsPe(finalDllPath);
  if (!peCheck.valid) {
    throw new ToolchainSetupError(`quickgui_host.dll failed PE validation: ${peCheck.error}`);
  }
  console.log(`[Toolchain Setup] Verified quickgui_host.dll PE (${peCheck.fileSize} bytes, ${peCheck.sha256})`);

  // 6. Verify CLI entrypoint
  const cliEntrypoint = join(toolchainDir, "packages", "cli", "src", "cli.ts");
  if (!existsSync(cliEntrypoint)) {
    throw new ToolchainSetupError(`QuickGUI CLI entrypoint not found at ${cliEntrypoint}`);
  }
  console.log(`[Toolchain Setup] Verified CLI entrypoint: ${cliEntrypoint}`);

  // 7. Save toolchain state to runner result
  const toolchainResult: ToolchainVerificationResult = {
    verified: true,
    repository: QUICKGUI_REPOSITORY,
    expectedRevision: PINNED_QUICKGUI_REVISION,
    verifiedRevision: headCommit,
    evidence: `Exact pinned Git commit ${headCommit} verified from ${QUICKGUI_REPOSITORY}`,
    cliVersion: "0.1.4-next.4",
    nativeVersion: "0.1.4-next.4",
    solidVersion: "0.1.4-next.4",
  };

  saveRunResult({
    pinnedToolchainDir: toolchainDir,
    pinnedCliEntrypoint: cliEntrypoint,
    pinnedHostLibrary: finalDllPath,
    quickguiToolchain: toolchainResult,
  });

  return {
    toolchainDir,
    gitCommit: headCommit,
    cliEntrypoint,
    hostLibraryPath: finalDllPath,
    verified: true,
  };
}

/**
 * Overlays @quickgui/* packages from the pinned toolchain into the app workspace.
 * Uses NTFS directory junctions (or copies) so zero files in the app are modified.
 * Because node_modules/ is volatile and excluded from sourceBundleHash, this preserves
 * the zero app mutation invariant.
 */
export function overlayPinnedToolchain(wsDir: string, toolchainDir: string): void {
  if (!existsSync(wsDir)) {
    throw new ToolchainSetupError(`Workspace directory does not exist: ${wsDir}`);
  }
  if (!existsSync(toolchainDir)) {
    throw new ToolchainSetupError(`Toolchain directory does not exist: ${toolchainDir}`);
  }

  const nodeModulesDir = join(wsDir, "node_modules");
  const quickguiScopeDir = join(nodeModulesDir, "@quickgui");
  mkdirSync(quickguiScopeDir, { recursive: true });

  const packages = [
    "cli",
    "native",
    "solid",
    "extension-terminal",
    "extension-updater",
  ];

  for (const pkg of packages) {
    const srcPkgDir = join(toolchainDir, "packages", pkg);
    if (!existsSync(srcPkgDir)) continue;

    const destPkgDir = join(quickguiScopeDir, pkg);
    try {
      if (existsSync(destPkgDir)) {
        rmSync(destPkgDir, { recursive: true, force: true });
      }
      symlinkSync(srcPkgDir, destPkgDir, "junction");
    } catch {
      // If symlink/junction fails (e.g. cross-volume in some environments), fall back to copy
      try {
        if (existsSync(destPkgDir)) {
          rmSync(destPkgDir, { recursive: true, force: true });
        }
        cpSync(srcPkgDir, destPkgDir, { recursive: true });
      } catch (copyErr) {
        console.warn(`[Toolchain Overlay] Warning: could not overlay package ${pkg}: ${copyErr}`);
      }
    }
  }

  console.log(`[Toolchain Overlay] Overlaid @quickgui packages from ${toolchainDir} into ${quickguiScopeDir}`);
}

if (import.meta.main) {
  try {
    const staged = setupPinnedToolchain();
    console.log(`[Toolchain Setup] Successfully verified and staged pinned QuickGUI toolchain at ${staged.toolchainDir}`);
  } catch (err) {
    const code = (err as { code?: string })?.code || "QUICKGUI_PROVENANCE_UNVERIFIED";
    const msg = (err as Error)?.message ?? String(err);
    console.error(`[Toolchain Setup] FAIL CLOSED: ${code} - ${msg}`);
    saveRunResult({
      stepFailed: true,
      errorCode: code,
      errorMessage: msg,
      quickguiToolchain: {
        verified: false,
        errorCode: code,
        errorMessage: msg,
        repository: QUICKGUI_REPOSITORY,
        expectedRevision: PINNED_QUICKGUI_REVISION,
      },
    });
    process.exit(1);
  }
}
