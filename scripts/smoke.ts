/**
 * Step 5 — mandatory native smoke test & preview capture.
 *
 * Ground rules (v0.9B):
 * 1. Process starts
 * 2. Process remains alive through the required settle interval
 * 3. Process does NOT terminate early (even with exit code 0!)
 * 4. Native window is discovered and verified to belong to process or child
 * 5. Screenshot capture succeeds with valid PNG header bytes and non-zero size
 *
 * FAIL CLOSED:
 * - SMOKE_FAILED if process exits early, crashes, or window is not found
 * - PREVIEW_CAPTURE_FAILED if preview screenshot is missing or corrupted
 */
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { loadRunResult, saveRunResult } from "./r2.ts";

export interface SmokeTestResult {
  passed: boolean;
  errorCode?: string;
  errorMessage?: string;
  pid?: number;
  childPids?: number[];
  startTime?: string;
  settleDurationMs?: number;
  exitCode?: number | null;
  aliveStatus: boolean;
  windowHandle?: string;
  windowDiscoveryTimeMs?: number;
  previewCaptured: boolean;
  previewSha256?: string;
  previewSize?: number;
}

export function validatePngHeader(bytes: Uint8Array): boolean {
  // PNG Magic Header: 89 50 4E 47 0D 0A 1A 0A
  const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== PNG_MAGIC[i]) return false;
  }
  return true;
}

export async function runNativeSmokeTest(
  exePath: string,
  wsDir: string,
  settleMs = 5000,
): Promise<SmokeTestResult> {
  const result: SmokeTestResult = {
    passed: false,
    aliveStatus: false,
    previewCaptured: false,
  };

  if (!exePath || !existsSync(exePath)) {
    result.errorCode = "SMOKE_FAILED";
    result.errorMessage = `Executable not found for smoke test: ${exePath}`;
    return result;
  }

  const startTime = new Date().toISOString();
  result.startTime = startTime;
  const t0 = performance.now();

  let child: ReturnType<typeof Bun.spawn> | null = null;
  let pid: number | undefined;

  try {
    child = Bun.spawn([exePath], {
      cwd: join(exePath, ".."),
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
    });
    pid = (child as unknown as { pid: number }).pid;
    result.pid = pid;

    let stdoutBuf = "";
    let stderrBuf = "";
    const readStream = async (
      stream: unknown,
      append: (chunk: string) => void,
    ) => {
      if (!stream || typeof (stream as ReadableStream).getReader !== "function") return;
      try {
        const reader = (stream as ReadableStream<Uint8Array>).getReader();
        const decoder = new TextDecoder();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          append(decoder.decode(value, { stream: true }));
        }
      } catch {
        /* ignore */
      }
    };
    readStream(child.stdout, (chunk) => {
      stdoutBuf = (stdoutBuf + chunk).slice(-32768);
    });
    readStream(child.stderr, (chunk) => {
      stderrBuf = (stderrBuf + chunk).slice(-32768);
    });

    // Check window discovery and capture preview using capture-window.ps1
    const script = join(import.meta.dir, "capture-window.ps1");
    const outPng = join(wsDir, "artifacts", "preview.png");
    mkdirSync(join(wsDir, "artifacts"), { recursive: true });

    const winCaptureStart = performance.now();
    const capRes = Bun.spawnSync(
      [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script,
        "-ProcessId",
        String(pid),
        "-OutputPath",
        outPng,
        "-TimeoutMs",
        "15000",
      ],
      { stdin: "ignore", stdout: "pipe", stderr: "pipe" },
    );

    const winCaptureElapsed = Math.round(performance.now() - winCaptureStart);
    result.windowDiscoveryTimeMs = winCaptureElapsed;

    const capOutput = new TextDecoder().decode(capRes.stdout).trim();
    if (capOutput.startsWith("SUCCESS:")) {
      result.windowHandle = capOutput;
    }

    // Wait for the required settle duration
    await new Promise((r) => setTimeout(r, settleMs));

    const totalDuration = Math.round(performance.now() - t0);
    result.settleDurationMs = totalDuration;

    // CRITICAL: Check process lifetime
    // If exitCode !== null, the process exited early (even code 0 is an error for desktop GUI!)
    const exitCode = (child as unknown as { exitCode: number | null }).exitCode;
    result.exitCode = exitCode;

    if (exitCode !== null) {
      result.aliveStatus = false;
      result.errorCode = "SMOKE_FAILED";
      const details = [stderrBuf.trim(), stdoutBuf.trim()].filter(Boolean).join(" | ");
      result.errorMessage = `Application exited early (exitCode=${exitCode}) during the settle window.${details ? ` Output: ${details}` : ""}`;
      console.error(`[Smoke] FAIL: ${result.errorMessage}`);
      return result;
    }

    result.aliveStatus = true;

    // Verify native window was found
    if (!capOutput.startsWith("SUCCESS:")) {
      result.errorCode = "SMOKE_FAILED";
      result.errorMessage = `Native window discovery failed: ${capOutput || new TextDecoder().decode(capRes.stderr).trim() || "No window handle detected"}`;
      console.error(`[Smoke] FAIL: ${result.errorMessage}`);
      return result;
    }

    // Verify preview screenshot
    if (!existsSync(outPng)) {
      result.errorCode = "PREVIEW_CAPTURE_FAILED";
      result.errorMessage = "Preview screenshot file artifacts/preview.png does not exist.";
      console.error(`[Smoke] FAIL: ${result.errorMessage}`);
      return result;
    }

    const pngBytes = new Uint8Array(readFileSync(outPng));
    if (pngBytes.length === 0) {
      result.errorCode = "PREVIEW_CAPTURE_FAILED";
      result.errorMessage = "Preview screenshot file is empty (0 bytes).";
      console.error(`[Smoke] FAIL: ${result.errorMessage}`);
      return result;
    }

    if (!validatePngHeader(pngBytes)) {
      result.errorCode = "PREVIEW_CAPTURE_FAILED";
      result.errorMessage = "Preview screenshot does not contain a valid PNG signature.";
      console.error(`[Smoke] FAIL: ${result.errorMessage}`);
      return result;
    }

    const previewSha = createHash("sha256").update(pngBytes).digest("hex");
    result.previewCaptured = true;
    result.previewSha256 = previewSha;
    result.previewSize = pngBytes.length;
    result.passed = true;

    console.log(`[Smoke] PASSED: Native window captured (${pngBytes.length} bytes, sha: ${previewSha}). Application remained active.`);
    return result;
  } catch (err) {
    result.aliveStatus = false;
    result.errorCode = "SMOKE_FAILED";
    result.errorMessage = `Smoke test execution threw: ${(err as Error)?.message ?? err}`;
    console.error(`[Smoke] FAIL: ${result.errorMessage}`);
    return result;
  } finally {
    // Graceful and forced process tree termination
    if (pid) {
      try {
        Bun.spawnSync(["taskkill", "/PID", String(pid), "/T", "/F"], {
          stdin: "ignore",
          stdout: "ignore",
          stderr: "ignore",
        });
      } catch {
        /* ignore */
      }
    }
    if (child) {
      try {
        (child as unknown as { kill: () => void }).kill();
      } catch {
        /* ignore */
      }
    }
  }
}

if (import.meta.main) {
  const run = loadRunResult();
  const wsDir = run.wsDir;
  const exePath = (run.finalExe as string) || (run.intermediateExe as string);

  const res = await runNativeSmokeTest(exePath, wsDir);
  saveRunResult({ smokeResult: res });

  if (!res.passed) {
    saveRunResult({
      stepFailed: true,
      errorCode: res.errorCode || "SMOKE_FAILED",
      errorMessage: res.errorMessage || "Native smoke test failed.",
    });
    process.exit(1);
  }
}
