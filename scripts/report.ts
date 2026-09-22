/**
 * Step 8 — report completion to backend callback (always runs).
 *
 * CRITICAL INVARIANT (v0.9B):
 * The worker MUST NEVER report status = "succeeded" unless every mandatory
 * acceptance condition passes and acceptance status is "accepted".
 *
 * Granular error codes:
 * - PROVENANCE_MISMATCH
 * - SOURCE_HASH_MISMATCH
 * - QUICKGUI_PROVENANCE_UNVERIFIED
 * - DEPENDENCY_INSTALL_FAILED
 * - CHECK_FAILED
 * - BUILD_FAILED
 * - CORRUPT_PE
 * - PACKAGING_FAILED
 * - SECURITY_VALIDATION_FAILED
 * - SMOKE_FAILED
 * - PREVIEW_CAPTURE_FAILED
 * - ARTIFACT_UPLOAD_FAILED
 * - CALLBACK_FAILED
 */
import { loadRunResult } from "./r2.ts";
import type { NativeAcceptanceReport } from "./generate-acceptance.ts";

export interface CallbackPayload {
  job_id: string;
  status: "succeeded" | "failed";
  app_id: string;
  build_id: string;
  generation_contract_hash?: string;
  source_bundle_hash?: string;
  quickgui_repository?: string;
  quickgui_revision?: string;
  target_platform?: string;
  target_arch?: string;
  acceptance_status?: string;
  acceptance_report?: NativeAcceptanceReport;
  artifact_key?: string;
  artifact_sha256?: string;
  artifact_size?: number;
  file_name?: string;
  preview_key?: string;
  preview_sha256?: string;
  evidence_keys?: Record<string, string>;
  runtime_evidence_status?: string;
  runtime_evidence_manifest_key?: string;
  runtime_evidence_manifest_sha256?: string;
  runtime_evidence_summary?: {
    total: number;
    passed: number;
    failed: number;
    uncertain: number;
  };
  release_status?: string[];
  events?: Array<{ kind: string; payload?: Record<string, unknown> }>;
  error_code?: string;
  error_message?: string;
}

export function buildCallbackPayload(): CallbackPayload {
  const run = loadRunResult();
  const stepFailed = Boolean(run.stepFailed || (process.env.ADORABLE_STEP_FAILED ?? "") === "1");
  const report = run.nativeAcceptanceReport as NativeAcceptanceReport | undefined;

  // Strict acceptance check: status is succeeded ONLY if accepted === true and NO step failed
  const isAccepted = Boolean(report?.accepted && report?.status === "accepted" && !stepFailed);

  const status: "succeeded" | "failed" = isAccepted ? "succeeded" : "failed";

  const payload: CallbackPayload = {
    job_id: (process.env.ADORABLE_JOB_ID ?? run.jobId) || "",
    status,
    app_id: (process.env.ADORABLE_APP_ID ?? run.appId) || "",
    build_id: (process.env.ADORABLE_BUILD_ID ?? run.buildId) || "",
    generation_contract_hash: (run.generationContractHash as string) || (report?.contractHash),
    source_bundle_hash: (run.computedSourceBundleHash as string) || (report?.sourceBundleHash),
    quickgui_repository: "https://github.com/egoist/quickgui.git",
    quickgui_revision: (run.quickguiRevision as string) || (report?.quickguiRevision),
    target_platform: (run.targetPlatform as string) || (report?.targetPlatform) || "windows",
    target_arch: (run.targetArch as string) || (report?.targetArch) || "x64",
    acceptance_status: report?.status || (isAccepted ? "accepted" : "build-failed"),
    acceptance_report: report,
    release_status: isAccepted ? ["BUILD_SUCCEEDED", "ACCEPTED"] : ["BUILD_FAILED"],
    events: [
      {
        kind: "remote-complete",
        payload: {
          accepted: isAccepted,
          acceptanceStatus: report?.status,
          launchOk: (run.smokeResult as Record<string, unknown>)?.aliveStatus ?? null,
          previewOk: (run.smokeResult as Record<string, unknown>)?.previewCaptured ?? null,
        },
      },
    ],
  };

  if (typeof run.artifactKey === "string") payload.artifact_key = run.artifactKey;
  if (typeof run.artifactSha256 === "string") payload.artifact_sha256 = run.artifactSha256;
  if (typeof run.artifactSize === "number") payload.artifact_size = run.artifactSize;
  if (typeof run.fileName === "string") payload.file_name = run.fileName;
  if (typeof run.previewKey === "string") payload.preview_key = run.previewKey;
  if (typeof run.previewSha256 === "string") payload.preview_sha256 = run.previewSha256;
  if (run.uploadedKeys && typeof run.uploadedKeys === "object") {
    payload.evidence_keys = run.uploadedKeys as Record<string, string>;
  }

  // Runtime evidence callback fields
  const evRes = run.runtimeEvidenceResult as {
    status?: string;
    manifestPath?: string;
    manifestSha256?: string;
  } | undefined;

  if (evRes?.status) {
    payload.runtime_evidence_status = evRes.status.toLowerCase();
  }
  if (typeof run.runtimeEvidenceManifestKey === "string") {
    payload.runtime_evidence_manifest_key = run.runtimeEvidenceManifestKey;
  }
  if (typeof run.runtimeEvidenceManifestSha256 === "string") {
    payload.runtime_evidence_manifest_sha256 = run.runtimeEvidenceManifestSha256;
  } else if (evRes?.manifestSha256) {
    payload.runtime_evidence_manifest_sha256 = evRes.manifestSha256;
  }

  if (!isAccepted) {
    // Determine the precise granular error code
    const explicitErrorCode = (run.errorCode as string);
    if (explicitErrorCode) {
      payload.error_code = explicitErrorCode;
      payload.error_message = (run.errorMessage as string) || `Build failed with ${explicitErrorCode}`;
    } else if (report?.status === "contract-failed") {
      payload.error_code = "PROVENANCE_MISMATCH";
      payload.error_message = report.blockers.join("; ") || "Contract validation failed.";
    } else if (report?.status === "security-failed") {
      payload.error_code = "SECURITY_VALIDATION_FAILED";
      payload.error_message = report.blockers.join("; ") || "Security scan failed.";
    } else if (report?.status === "check-failed") {
      payload.error_code = "CHECK_FAILED";
      payload.error_message = report.blockers.join("; ") || "QuickGUI check failed.";
    } else if (report?.status === "build-failed") {
      payload.error_code = "BUILD_FAILED";
      payload.error_message = report.blockers.join("; ") || "QuickGUI build failed.";
    } else if (report?.status === "launch-failed") {
      payload.error_code = "SMOKE_FAILED";
      payload.error_message = report.blockers.join("; ") || "Launch smoke test failed.";
    } else if (report?.status === "evidence-failed") {
      payload.error_code = "EVIDENCE_EXECUTION_FAILED";
      payload.error_message = report.blockers.join("; ") || "Runtime evidence execution failed.";
    } else {
      payload.error_code = "REMOTE_BUILD_FAILED";
      payload.error_message = "The remote Windows build did not complete successfully.";
    }
  }

  return payload;
}

export async function sendCompletionReport(
  callbackUrl: string,
  secret: string,
  payload: CallbackPayload,
): Promise<boolean> {
  if (!callbackUrl) throw new Error("Callback URL is missing.");
  if (!secret) throw new Error("Callback secret is missing.");

  let delivered = false;
  let lastError = "";

  for (let attempt = 1; attempt <= 3 && !delivered; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30000);
      try {
        const res = await fetch(callbackUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${secret}`,
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        if (res.ok) {
          delivered = true;
        } else {
          lastError = `HTTP ${res.status}`;
        }
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      lastError = String((err as Error)?.message ?? err).slice(0, 120);
    }
    if (!delivered && attempt < 3) {
      console.log(`[Report] Attempt ${attempt} failed (${lastError}), retrying in 60s...`);
      await new Promise((r) => setTimeout(r, 60000));
    }
  }

  if (!delivered) {
    console.error(`[Report] Callback not delivered after 3 attempts (${lastError}).`);
    return false;
  }

  console.log(`[Report] Completion reported successfully: status="${payload.status}", error_code="${payload.error_code ?? 'none'}".`);
  return true;
}

if (import.meta.main) {
  const callbackUrl = process.env.ADORABLE_CALLBACK_URL ?? "";
  const secret = process.env.ADORABLE_CALLBACK_SECRET ?? "";
  const payload = buildCallbackPayload();

  const success = await sendCompletionReport(callbackUrl, secret, payload);
  if (!success) {
    process.exit(1);
  }
}
