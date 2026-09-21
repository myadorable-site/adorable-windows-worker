/**
 * Steps 3 & 4 — execute `quickgui check` and `quickgui build` via verified pinned toolchain.
 *
 * Implements:
 * - Direct execution of pinned QuickGUI CLI entrypoint (bun <toolchain>/packages/cli/src/cli.ts)
 * - Explicit QUICKGUI_LIBRARY pointing to verified quickgui_host.dll
 * - Rejection of floating/unverified CLI (fails closed with QUICKGUI_PROVENANCE_UNVERIFIED)
 * - Unambiguous executable discovery in dist/windows-x64/<AppName>.exe
 * - Initial PE verification on intermediate executable
 * - Structured evidence recording for NativeAcceptanceReport
 */
import { existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { loadRunResult, saveRunResult } from "./r2.ts";
import { validateWindowsPe, type PeValidationResult } from "./pe-validator.ts";

export interface StepExecutionEvidence {
  command: string;
  startTime: string;
  endTime: string;
  durationMs: number;
  exitCode: number;
  stdout: string;
  stderr: string;
  discoveredOutputPaths?: string[];
  peValidation?: PeValidationResult;
  cliEntrypoint?: string;
  hostLibrary?: string;
}

export function resolvePinnedCliCommand(subcommand: "check" | "build"): {
  cmd: string[];
  extraEnv: Record<string, string>;
  cliEntrypoint: string;
  hostLibrary: string;
} {
  const run = loadRunResult();
  let cliEntrypoint =
    (run.pinnedCliEntrypoint as string) ||
    process.env.ADORABLE_QUICKGUI_CLI ||
    "";
  let hostLibrary =
    (run.pinnedHostLibrary as string) ||
    process.env.QUICKGUI_LIBRARY ||
    "";

  if (!cliEntrypoint || !existsSync(cliEntrypoint)) {
    const candidateDirs = [
      run.pinnedToolchainDir as string,
      process.env.ADORABLE_QUICKGUI_SOURCE_DIR,
      process.env.RUNNER_TEMP ? join(process.env.RUNNER_TEMP, "quickgui-pinned") : "",
    ].filter(Boolean) as string[];

    for (const d of candidateDirs) {
      const candidateCli = resolve(d, "packages", "cli", "src", "cli.ts");
      if (existsSync(candidateCli)) {
        cliEntrypoint = candidateCli;
        if (!hostLibrary) {
          const winX64Dll = resolve(d, "packages", "native", "lib", "windows-x64", "quickgui_host.dll");
          const relDll = resolve(d, "target", "release", "quickgui_host.dll");
          if (existsSync(winX64Dll)) hostLibrary = winX64Dll;
          else if (existsSync(relDll)) hostLibrary = relDll;
        }
        break;
      }
    }
  }

  // Fallback for mock/synthetic tests if explicitly allowed
  if ((!cliEntrypoint || !existsSync(cliEntrypoint)) && process.env.ADORABLE_ALLOW_BUNX_FALLBACK === "1") {
    return {
      cmd: ["bunx", "quickgui", subcommand],
      extraEnv: {},
      cliEntrypoint: "bunx-quickgui-fallback",
      hostLibrary: "",
    };
  }

  if (!cliEntrypoint || !existsSync(cliEntrypoint)) {
    throw new BuildStepError(
      "QUICKGUI_PROVENANCE_UNVERIFIED",
      "Pinned QuickGUI CLI entrypoint (packages/cli/src/cli.ts) not found. Building with unverified/floating CLI is rejected.",
    );
  }

  const extraEnv: Record<string, string> = {};
  if (hostLibrary && existsSync(hostLibrary)) {
    extraEnv.QUICKGUI_LIBRARY = hostLibrary;
  }

  return {
    cmd: ["bun", cliEntrypoint, subcommand],
    extraEnv,
    cliEntrypoint,
    hostLibrary,
  };
}

export function executeCommand(
  cmd: string[],
  wsDir: string,
  extraEnv?: Record<string, string>,
): { exitCode: number; stdout: string; stderr: string; durationMs: number; startTime: string; endTime: string } {
  const startTime = new Date().toISOString();
  const t0 = performance.now();

  const res = spawnSync(cmd[0], cmd.slice(1), {
    cwd: wsDir,
    encoding: "utf8",
    env: { ...process.env, ...extraEnv },
  });

  const t1 = performance.now();
  const endTime = new Date().toISOString();

  return {
    exitCode: res.status ?? 1,
    stdout: res.stdout || "",
    stderr: res.stderr || "",
    durationMs: Math.round(t1 - t0),
    startTime,
    endTime,
  };
}

export function runQuickGuiCheck(wsDir: string): StepExecutionEvidence {
  console.log("[QuickGUI Check] Resolving pinned QuickGUI CLI for check...");
  const { cmd, extraEnv, cliEntrypoint, hostLibrary } = resolvePinnedCliCommand("check");
  console.log(`[QuickGUI Check] Executing: ${cmd.join(" ")} in ${wsDir}`);
  const res = executeCommand(cmd, wsDir, extraEnv);

  const evidence: StepExecutionEvidence = {
    command: cmd.join(" "),
    startTime: res.startTime,
    endTime: res.endTime,
    durationMs: res.durationMs,
    exitCode: res.exitCode,
    stdout: res.stdout,
    stderr: res.stderr,
    cliEntrypoint,
    hostLibrary,
  };

  saveRunResult({ checkEvidence: evidence });

  if (res.exitCode !== 0) {
    saveRunResult({
      stepFailed: true,
      errorCode: "CHECK_FAILED",
      errorMessage: `quickgui check failed with exit code ${res.exitCode}: ${res.stderr.slice(0, 300) || res.stdout.slice(0, 300)}`,
    });
    console.error(`[QuickGUI Check] FAILED: exit code ${res.exitCode}`);
  } else {
    console.log(`[QuickGUI Check] PASSED (${res.durationMs}ms)`);
  }

  return evidence;
}

export function runQuickGuiBuild(wsDir: string): StepExecutionEvidence {
  console.log("[QuickGUI Build] Resolving pinned QuickGUI CLI for build...");
  const { cmd, extraEnv, cliEntrypoint, hostLibrary } = resolvePinnedCliCommand("build");
  console.log(`[QuickGUI Build] Executing: ${cmd.join(" ")} in ${wsDir}`);
  const res = executeCommand(cmd, wsDir, extraEnv);

  // Discover output paths in dist/
  const discovered: string[] = [];
  const distDir = join(wsDir, "dist");
  if (existsSync(distDir)) {
    const walk = (d: string) => {
      try {
        for (const e of readdirSync(d, { withFileTypes: true })) {
          const p = join(d, e.name);
          if (e.isDirectory()) walk(p);
          else discovered.push(p);
        }
      } catch {
        /* ignore */
      }
    };
    walk(distDir);
  }

  const evidence: StepExecutionEvidence = {
    command: cmd.join(" "),
    startTime: res.startTime,
    endTime: res.endTime,
    durationMs: res.durationMs,
    exitCode: res.exitCode,
    stdout: res.stdout,
    stderr: res.stderr,
    discoveredOutputPaths: discovered,
    cliEntrypoint,
    hostLibrary,
  };

  saveRunResult({ buildEvidence: evidence });

  if (res.exitCode !== 0) {
    saveRunResult({
      stepFailed: true,
      errorCode: "BUILD_FAILED",
      errorMessage: `quickgui build failed with exit code ${res.exitCode}: ${res.stderr.slice(0, 300) || res.stdout.slice(0, 300)}`,
    });
    console.error(`[QuickGUI Build] FAILED: exit code ${res.exitCode}`);
    return evidence;
  }

  console.log(`[QuickGUI Build] PASSED (${res.durationMs}ms)`);
  return evidence;
}

/**
 * Discovers the exact QuickGUI-produced Windows executable unambiguously.
 * Expected location: dist/windows-x64/<AppName>.exe
 */
export function discoverAndVerifyIntermediateExe(wsDir: string): {
  exePath: string;
  peValidation: PeValidationResult;
} {
  const distDir = join(wsDir, "dist");
  if (!existsSync(distDir)) {
    throw new BuildStepError("BUILD_FAILED", "dist/ directory does not exist after build.");
  }

  // Look specifically in dist/windows-x64/ or dist/
  const candidates: string[] = [];
  const walk = (dir: string) => {
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (
          entry.name.toLowerCase().endsWith(".exe") &&
          !entry.name.toLowerCase().endsWith(".payload.exe")
        ) {
          candidates.push(full);
        }
      }
    } catch {
      /* ignore */
    }
  };

  walk(distDir);

  if (candidates.length === 0) {
    throw new BuildStepError("BUILD_FAILED", "No executable found in dist/ directory.");
  }

  // Prefer dist/windows-x64/*.exe if multiple found
  const winX64Candidates = candidates.filter((c) =>
    c.replace(/\\/g, "/").includes("/windows-x64/"),
  );
  const selectedExe = winX64Candidates.length === 1 ? winX64Candidates[0] : candidates[0];

  if (candidates.length > 1 && winX64Candidates.length !== 1) {
    throw new BuildStepError(
      "BUILD_FAILED",
      `Ambiguous executable selection: found multiple executables: ${candidates.join(", ")}`,
    );
  }

  console.log(`[Executable Discovery] Selected intermediate executable: ${selectedExe}`);

  // Run deterministic PE verification on intermediate executable
  const peRes = validateWindowsPe(selectedExe);
  if (!peRes.valid) {
    throw new BuildStepError("CORRUPT_PE", `Intermediate executable PE validation failed: ${peRes.error}`);
  }

  saveRunResult({
    intermediateExe: selectedExe,
    intermediatePeValidation: peRes,
  });

  return { exePath: selectedExe, peValidation: peRes };
}

export class BuildStepError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "BuildStepError";
  }
}

// CLI dispatcher
if (import.meta.main) {
  const action = process.argv[2];
  const wsDir = loadRunResult().wsDir;

  if (action === "check") {
    try {
      const res = runQuickGuiCheck(wsDir);
      if (res.exitCode !== 0) process.exit(1);
    } catch (err) {
      const code = (err as { code?: string })?.code || "CHECK_FAILED";
      const msg = (err as Error)?.message ?? String(err);
      console.error(`[QuickGUI Check] FAIL CLOSED: ${code} - ${msg}`);
      saveRunResult({ stepFailed: true, errorCode: code, errorMessage: msg });
      process.exit(1);
    }
  } else if (action === "build") {
    try {
      const res = runQuickGuiBuild(wsDir);
      if (res.exitCode !== 0) process.exit(1);
      discoverAndVerifyIntermediateExe(wsDir);
    } catch (err) {
      const code = (err as { code?: string })?.code || "BUILD_FAILED";
      const msg = (err as Error)?.message ?? String(err);
      console.error(`[Build] FAIL CLOSED: ${code} - ${msg}`);
      saveRunResult({ stepFailed: true, errorCode: code, errorMessage: msg });
      process.exit(1);
    }
  }
}
