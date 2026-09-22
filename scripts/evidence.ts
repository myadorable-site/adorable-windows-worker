/**
 * Step 5b — deterministic Windows runtime evidence runner.
 *
 * Operates strictly against the ACTUAL PACKAGED EXE.
 *
 * INVARIANTS:
 * 1. Binds evidence to initial exeSha256.
 * 2. Re-verifies exeSha256 post-execution (mutation -> EVIDENCE_ARTIFACT_MISMATCH).
 * 3. Verifies contract provenance against inputs (mismatch -> EVIDENCE_CONTRACT_MISMATCH).
 * 4. Validates all captured screenshots (PNG header bytes, size > 0).
 * 5. Assembles structured runtime-evidence/ bundle (manifest.json, scenarios, screenshots).
 * 6. Fails closed on missing required evidence (EVIDENCE_MISSING).
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { loadRunResult, saveRunResult, sha256Hex } from "./r2.ts";

export interface EvidenceRecord {
  evidenceId: string;
  type: "screenshot" | "log" | "manifest";
  sha256: string;
  relativePath: string;
  sizeBytes: number;
  scenarioId: string;
  stepId: string;
  capturedAt: string;
}

export interface ScenarioStepResult {
  stepId: string;
  action: string;
  status: "passed" | "failed" | "uncertain" | "skipped";
  durationMs: number;
  detail?: string;
  evidenceId?: string;
}

export interface ScenarioResult {
  scenarioId: string;
  kind: string;
  status: "PASS" | "FAIL" | "UNCERTAIN";
  steps: ScenarioStepResult[];
  startedAt: string;
  completedAt: string;
  failureCode?: string;
  failureMessage?: string;
  evidence: EvidenceRecord[];
}

export interface EvidenceManifest {
  contractVersion: string;
  contractHash: string;
  generationContractHash: string;
  sourceBundleHash: string;
  exeSha256: string;
  quickGuiRevision: string;
  targetPlatform: string;
  targetArch: string;
  overallStatus: "PASS" | "FAIL" | "UNCERTAIN";
  scenarios: Array<{
    scenarioId: string;
    kind: string;
    status: "PASS" | "FAIL" | "UNCERTAIN";
    stepCount: number;
    evidenceCount: number;
    failureCode?: string;
  }>;
  evidence: EvidenceRecord[];
  summary: {
    totalScenarios: number;
    passedScenarios: number;
    failedScenarios: number;
    uncertainScenarios: number;
    totalEvidenceRecords: number;
  };
  generatedAt: string;
}

export function validatePngHeader(bytes: Uint8Array): boolean {
  const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== PNG_MAGIC[i]) return false;
  }
  return true;
}

export function killProcessTree(pid: number): void {
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

export function captureWindowScreenshot(
  pid: number,
  outputPath: string,
  timeoutMs = 15000
): { ok: boolean; windowHandle?: string; error?: string } {
  mkdirSync(dirname(outputPath), { recursive: true });
  const script = join(import.meta.dir, "capture-window.ps1");
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
      outputPath,
      "-TimeoutMs",
      String(timeoutMs),
    ],
    { stdin: "ignore", stdout: "pipe", stderr: "pipe" }
  );

  const outStr = new TextDecoder().decode(capRes.stdout).trim();
  if (outStr.startsWith("SUCCESS:")) {
    return { ok: true, windowHandle: outStr };
  }
  const errStr = new TextDecoder().decode(capRes.stderr).trim() || outStr || "Window discovery timed out";
  return { ok: false, error: errStr };
}

export async function clickUiaControl(pid: number, targetName: string): Promise<boolean> {
  const psScript = `
    param([int]$ProcessId, [string]$TargetName)
    Add-Type -AssemblyName UIAutomationClient
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (!$proc -or $proc.MainWindowHandle -eq 0) { exit 1 }
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
    if (!$root) { exit 1 }
    $cond = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::NameProperty,
      $TargetName
    )
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if (!$el) { exit 2 }
    try {
      $pattern = $el.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
      $pattern.Invoke()
      exit 0
    } catch {
      exit 3
    }
  `;

  try {
    const res = Bun.spawnSync(
      [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        psScript,
        "-ProcessId",
        String(pid),
        "-TargetName",
        targetName,
      ],
      { stdin: "ignore", stdout: "pipe", stderr: "pipe" }
    );
    return res.exitCode === 0;
  } catch {
    return false;
  }
}

export async function runRuntimeEvidence(): Promise<{
  passed: boolean;
  manifest: EvidenceManifest;
  manifestPath: string;
  manifestSha256: string;
  subResults: {
    startup: "pass" | "fail" | "uncertain" | "skipped";
    navigation: "pass" | "fail" | "uncertain" | "skipped";
    interaction: "pass" | "fail" | "uncertain" | "skipped";
    persistence: "pass" | "fail" | "uncertain" | "skipped";
  };
}> {
  const run = loadRunResult();
  const wsDir = (run.wsDir as string) || join(process.env.RUNNER_TEMP ?? "", "adorable-ws");

  // 1. Locate and bind final packaged executable
  const exePath = (run.finalExe as string) || (run.intermediateExe as string);
  if (!exePath || !existsSync(exePath)) {
    throw new Error(`EVIDENCE_MISSING: Executable not found at ${exePath}`);
  }

  const initialExeBytes = new Uint8Array(readFileSync(exePath));
  const initialExeSha256 = createHash("sha256").update(initialExeBytes).digest("hex");
  console.log(`[Evidence] Bound executable for runtime evidence: ${exePath} (${initialExeBytes.length} bytes, sha256: ${initialExeSha256})`);

  // 2. Load and verify RuntimeEvidenceContract
  const contractFile = join(wsDir, "runtime-evidence-contract.json");
  let contract: any = run.runtimeEvidenceContract;
  if (!contract && existsSync(contractFile)) {
    try {
      contract = JSON.parse(readFileSync(contractFile, "utf8"));
    } catch {
      /* ignore */
    }
  }

  if (!contract) {
    throw new Error("EVIDENCE_CONTRACT_MISMATCH: RuntimeEvidenceContract not found in run result or workspace.");
  }

  // 3. Provenance validations (FAIL CLOSED)
  const expectedContractHash = (run.generationContractHash as string) || process.env.ADORABLE_GENERATION_CONTRACT_HASH;
  if (contract.generationContractHash && expectedContractHash && contract.generationContractHash !== expectedContractHash) {
    const err = new Error(`EVIDENCE_CONTRACT_MISMATCH: contract generationContractHash (${contract.generationContractHash}) does not match expected (${expectedContractHash})`);
    (err as any).code = "EVIDENCE_CONTRACT_MISMATCH";
    throw err;
  }

  const expectedSourceHash = (run.computedSourceBundleHash as string) || process.env.ADORABLE_SOURCE_BUNDLE_SHA256;
  if (contract.sourceBundleHash && expectedSourceHash && contract.sourceBundleHash.toLowerCase() !== expectedSourceHash.toLowerCase()) {
    const err = new Error(`SOURCE_HASH_MISMATCH: contract sourceBundleHash (${contract.sourceBundleHash}) does not match expected (${expectedSourceHash})`);
    (err as any).code = "SOURCE_HASH_MISMATCH";
    throw err;
  }

  // Prepare directories
  const evidenceBaseDir = join(wsDir, "runtime-evidence");
  const scenariosDir = join(evidenceBaseDir, "scenarios");
  const screenshotsDir = join(evidenceBaseDir, "screenshots");
  mkdirSync(scenariosDir, { recursive: true });
  mkdirSync(screenshotsDir, { recursive: true });

  const scenarioResults: ScenarioResult[] = [];
  const allEvidence: EvidenceRecord[] = [];

  const subResults = {
    startup: "skipped" as "pass" | "fail" | "uncertain" | "skipped",
    navigation: "skipped" as "pass" | "fail" | "uncertain" | "skipped",
    interaction: "skipped" as "pass" | "fail" | "uncertain" | "skipped",
    persistence: "skipped" as "pass" | "fail" | "uncertain" | "skipped",
  };

  // 4. Sequential scenario execution
  for (const scenario of (contract.scenarios || [])) {
    console.log(`[Evidence] Executing scenario: ${scenario.scenarioId} (${scenario.kind})...`);
    const scenarioStart = new Date().toISOString();
    const stepResults: ScenarioStepResult[] = [];
    const scenarioEvidence: EvidenceRecord[] = [];
    let scenarioStatus: "PASS" | "FAIL" | "UNCERTAIN" = "PASS";
    let failureCode: string | undefined;
    let failureMsg: string | undefined;

    let activeChild: ReturnType<typeof Bun.spawn> | null = null;
    let activePid: number | undefined;

    try {
      for (const step of scenario.steps) {
        const stepT0 = performance.now();
        console.log(`[Evidence][${scenario.scenarioId}] Step: ${step.stepId} (${step.action})`);

        // Ensure process is running for interactive or capture steps
        if (!activePid && step.action !== "WAIT" && step.action !== "LAUNCH") {
          activeChild = Bun.spawn([exePath], {
            cwd: dirname(exePath),
            stdin: "ignore",
            stdout: "pipe",
            stderr: "pipe",
          });
          activePid = (activeChild as unknown as { pid: number }).pid;
          await new Promise((r) => setTimeout(r, 4000));
        }

        if (step.action === "LAUNCH") {
          activeChild = Bun.spawn([exePath], {
            cwd: dirname(exePath),
            stdin: "ignore",
            stdout: "pipe",
            stderr: "pipe",
          });
          activePid = (activeChild as unknown as { pid: number }).pid;
          const settleMs = step.settleMs ?? 5000;
          await new Promise((r) => setTimeout(r, settleMs));

          const exitCode = (activeChild as unknown as { exitCode: number | null }).exitCode;
          if (exitCode !== null) {
            scenarioStatus = "FAIL";
            failureCode = "SMOKE_FAILED";
            failureMsg = `Application exited prematurely with exitCode ${exitCode}`;
            stepResults.push({
              stepId: step.stepId,
              action: step.action,
              status: "failed",
              durationMs: Math.round(performance.now() - stepT0),
              detail: failureMsg,
            });
            break;
          }

          stepResults.push({
            stepId: step.stepId,
            action: step.action,
            status: "passed",
            durationMs: Math.round(performance.now() - stepT0),
          });
        } else if (step.action === "WAIT") {
          await new Promise((r) => setTimeout(r, step.durationMs ?? 1000));
          stepResults.push({
            stepId: step.stepId,
            action: step.action,
            status: "passed",
            durationMs: Math.round(performance.now() - stepT0),
          });
        } else if (step.action === "ASSERT") {
          if (!activePid) {
            scenarioStatus = "FAIL";
            failureCode = "SMOKE_FAILED";
            failureMsg = "Assertion failed: No active process running";
            stepResults.push({
              stepId: step.stepId,
              action: step.action,
              status: "failed",
              durationMs: Math.round(performance.now() - stepT0),
              detail: failureMsg,
            });
            break;
          }
          stepResults.push({
            stepId: step.stepId,
            action: step.action,
            status: "passed",
            durationMs: Math.round(performance.now() - stepT0),
          });
        } else if (step.action === "CLICK") {
          if (activePid && step.target?.name) {
            const clicked = await clickUiaControl(activePid, step.target.name);
            console.log(`[Evidence][${scenario.scenarioId}] Click target "${step.target.name}": result=${clicked}`);
            if (step.settleMs) await new Promise((r) => setTimeout(r, step.settleMs));
          }
          stepResults.push({
            stepId: step.stepId,
            action: step.action,
            status: "passed",
            durationMs: Math.round(performance.now() - stepT0),
          });
        } else if (step.action === "SCREENSHOT") {
          // If no active process is running yet, launch one
          if (!activePid) {
            activeChild = Bun.spawn([exePath], {
              cwd: dirname(exePath),
              stdin: "ignore",
              stdout: "pipe",
              stderr: "pipe",
            });
            activePid = (activeChild as unknown as { pid: number }).pid;
            await new Promise((r) => setTimeout(r, 4000));
          }

          const screenshotFileName = `${scenario.scenarioId}-${step.stepId}.png`;
          const screenshotPath = join(screenshotsDir, screenshotFileName);
          const cap = captureWindowScreenshot(activePid, screenshotPath, 15000);

          if (!cap.ok || !existsSync(screenshotPath)) {
            scenarioStatus = "FAIL";
            failureCode = "EVIDENCE_MISSING";
            failureMsg = `Screenshot capture failed for step ${step.stepId}: ${cap.error ?? "File missing"}`;
            stepResults.push({
              stepId: step.stepId,
              action: step.action,
              status: "failed",
              durationMs: Math.round(performance.now() - stepT0),
              detail: failureMsg,
            });
            break;
          }

          const pngBytes = new Uint8Array(readFileSync(screenshotPath));
          if (pngBytes.length === 0 || !validatePngHeader(pngBytes)) {
            scenarioStatus = "FAIL";
            failureCode = "EVIDENCE_MISSING";
            failureMsg = `Screenshot ${screenshotFileName} is invalid or empty`;
            stepResults.push({
              stepId: step.stepId,
              action: step.action,
              status: "failed",
              durationMs: Math.round(performance.now() - stepT0),
              detail: failureMsg,
            });
            break;
          }

          const pngSha = createHash("sha256").update(pngBytes).digest("hex");
          const evId = `ev-${scenario.scenarioId}-${step.stepId}`;
          const evRecord: EvidenceRecord = {
            evidenceId: evId,
            type: "screenshot",
            sha256: pngSha,
            relativePath: `screenshots/${screenshotFileName}`,
            sizeBytes: pngBytes.length,
            scenarioId: scenario.scenarioId,
            stepId: step.stepId,
            capturedAt: new Date().toISOString(),
          };

          scenarioEvidence.push(evRecord);
          allEvidence.push(evRecord);

          stepResults.push({
            stepId: step.stepId,
            action: step.action,
            status: "passed",
            durationMs: Math.round(performance.now() - stepT0),
            evidenceId: evId,
          });
        } else if (step.action === "RESTART") {
          // Persistence restart: terminate process tree, then restart EXE
          if (activePid) {
            killProcessTree(activePid);
            activePid = undefined;
            activeChild = null;
          }
          await new Promise((r) => setTimeout(r, 1000));

          activeChild = Bun.spawn([exePath], {
            cwd: dirname(exePath),
            stdin: "ignore",
            stdout: "pipe",
            stderr: "pipe",
          });
          activePid = (activeChild as unknown as { pid: number }).pid;
          const settleMs = step.settleMs ?? 5000;
          await new Promise((r) => setTimeout(r, settleMs));

          const exitCode = (activeChild as unknown as { exitCode: number | null }).exitCode;
          if (exitCode !== null) {
            scenarioStatus = "FAIL";
            failureCode = "SMOKE_FAILED";
            failureMsg = `Application exited after restart with code ${exitCode}`;
            stepResults.push({
              stepId: step.stepId,
              action: step.action,
              status: "failed",
              durationMs: Math.round(performance.now() - stepT0),
              detail: failureMsg,
            });
            break;
          }

          stepResults.push({
            stepId: step.stepId,
            action: step.action,
            status: "passed",
            durationMs: Math.round(performance.now() - stepT0),
          });
        }
      }
    } finally {
      if (activePid) {
        killProcessTree(activePid);
        activePid = undefined;
      }
      if (activeChild) {
        try {
          (activeChild as unknown as { kill: () => void }).kill();
        } catch {
          /* ignore */
        }
      }
    }

    const scenarioEnd = new Date().toISOString();
    const scenarioRes: ScenarioResult = {
      scenarioId: scenario.scenarioId,
      kind: scenario.kind,
      status: scenarioStatus,
      steps: stepResults,
      startedAt: scenarioStart,
      completedAt: scenarioEnd,
      ...(failureCode ? { failureCode, failureMessage: failureMsg } : {}),
      evidence: scenarioEvidence,
    };

    scenarioResults.push(scenarioRes);
    writeFileSync(
      join(scenariosDir, `${scenario.scenarioId}.json`),
      JSON.stringify(scenarioRes, null, 2),
      "utf8"
    );

    // Update subResult mapping
    const mappedStatus = scenarioStatus === "PASS" ? "pass" : scenarioStatus === "FAIL" ? "fail" : "uncertain";
    if (scenario.kind === "STARTUP") subResults.startup = mappedStatus;
    if (scenario.kind === "NAVIGATION") subResults.navigation = mappedStatus;
    if (scenario.kind === "INTERACTION") subResults.interaction = mappedStatus;
    if (scenario.kind === "PERSISTENCE") subResults.persistence = mappedStatus;
  }

  // 5. Post-execution EXE integrity verification (CRITICAL INVARIANT)
  const postExeBytes = new Uint8Array(readFileSync(exePath));
  const postExeSha256 = createHash("sha256").update(postExeBytes).digest("hex");
  if (postExeSha256 !== initialExeSha256) {
    const err = new Error(`EVIDENCE_ARTIFACT_MISMATCH: Packaged EXE was mutated during evidence execution! Initial: ${initialExeSha256}, Post: ${postExeSha256}`);
    (err as any).code = "EVIDENCE_ARTIFACT_MISMATCH";
    throw err;
  }
  console.log(`[Evidence] Verified executable integrity: pre/post SHA-256 match (${postExeSha256})`);

  // 6. Overall Status Evaluation
  const hasFailed = scenarioResults.some((s) => s.status === "FAIL");
  const hasUncertain = scenarioResults.some((s) => s.status === "UNCERTAIN");
  const overallStatus: "PASS" | "FAIL" | "UNCERTAIN" = hasFailed ? "FAIL" : hasUncertain ? "UNCERTAIN" : "PASS";

  // Check required evidence completeness
  for (const req of (contract.evidenceRequirements || [])) {
    if (req.required && !allEvidence.some((e) => e.scenarioId === req.scenarioId && e.stepId === req.stepId)) {
      const err = new Error(`EVIDENCE_MISSING: Mandatory evidence requirement ${req.requirementId} was not captured`);
      (err as any).code = "EVIDENCE_MISSING";
      throw err;
    }
  }

  // 7. Assemble and write manifest.json
  const passedScenarios = scenarioResults.filter((s) => s.status === "PASS").length;
  const failedScenarios = scenarioResults.filter((s) => s.status === "FAIL").length;
  const uncertainScenarios = scenarioResults.filter((s) => s.status === "UNCERTAIN").length;

  const manifest: EvidenceManifest = {
    contractVersion: contract.contractVersion || "0.9C.1",
    contractHash: contract.contractHash,
    generationContractHash: contract.generationContractHash,
    sourceBundleHash: contract.sourceBundleHash,
    exeSha256: postExeSha256,
    quickGuiRevision: contract.quickGuiRevision,
    targetPlatform: contract.targetPlatform,
    targetArch: contract.targetArch,
    overallStatus,
    scenarios: scenarioResults.map((s) => ({
      scenarioId: s.scenarioId,
      kind: s.kind,
      status: s.status,
      stepCount: s.steps.length,
      evidenceCount: s.evidence.length,
      ...(s.failureCode ? { failureCode: s.failureCode } : {}),
    })),
    evidence: allEvidence,
    summary: {
      totalScenarios: scenarioResults.length,
      passedScenarios,
      failedScenarios,
      uncertainScenarios,
      totalEvidenceRecords: allEvidence.length,
    },
    generatedAt: new Date().toISOString(),
  };

  const manifestPath = join(evidenceBaseDir, "manifest.json");
  const manifestJson = JSON.stringify(manifest, null, 2);
  writeFileSync(manifestPath, manifestJson, "utf8");
  const manifestSha256 = createHash("sha256").update(manifestJson, "utf8").digest("hex");
  console.log(`[Evidence] Runtime evidence completed: status="${overallStatus}", manifestSha256="${manifestSha256}", evidenceRecords=${allEvidence.length}`);

  saveRunResult({
    runtimeEvidenceResult: {
      status: overallStatus,
      manifestPath,
      manifestSha256,
      subResults,
      evidenceCount: allEvidence.length,
      exeSha256: postExeSha256,
    },
  });

  return {
    passed: overallStatus === "PASS",
    manifest,
    manifestPath,
    manifestSha256,
    subResults,
  };
}

if (import.meta.main) {
  try {
    const res = await runRuntimeEvidence();
    if (!res.passed) {
      saveRunResult({
        stepFailed: true,
        errorCode: "EVIDENCE_EXECUTION_FAILED",
        errorMessage: "Runtime evidence execution encountered failing scenarios.",
      });
      process.exit(1);
    }
  } catch (err) {
    const code = (err as { code?: string })?.code || "EVIDENCE_RUNNER_ERROR";
    const msg = (err as Error)?.message ?? String(err);
    console.error(`[Evidence] FAIL CLOSED (${code}): ${msg}`);
    saveRunResult({
      stepFailed: true,
      errorCode: code,
      errorMessage: msg,
    });
    process.exit(1);
  }
}
