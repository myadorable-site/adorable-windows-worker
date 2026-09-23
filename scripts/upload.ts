/**
 * Step 7 — upload verified artifacts to R2 under ${app_id}/${build_id}/
 *
 * Uploads:
 * 1. Final standalone .exe
 * 2. preview.png
 * 3. native-generation-result.json
 * 4. native-acceptance.json
 *
 * FAIL CLOSED:
 * ARTIFACT_UPLOAD_FAILED if any mandatory upload fails.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { loadRunResult, r2Put, readCreds, saveRunResult, sha256Hex } from "./r2.ts";

function appPrefix(): string {
  const appId = (process.env.ADORABLE_APP_ID ?? "app").replace(/[^a-zA-Z0-9._-]/g, "");
  const buildId = (process.env.ADORABLE_BUILD_ID ?? "build").replace(/[^a-zA-Z0-9._-]/g, "");
  return `${appId}/${buildId}`;
}

export async function uploadArtifacts(wsDir: string): Promise<{
  uploadedKeys: Record<string, string>;
  hashes: Record<string, string>;
}> {
  const run = loadRunResult();
  const creds = readCreds();
  const prefix = appPrefix();

  const finalExe = (run.finalExe as string) || join(wsDir, "dist", "windows-x64", `${process.env.ADORABLE_APP_ID || "app"}.exe`);
  if (!finalExe || !existsSync(finalExe)) {
    throw new UploadError("ARTIFACT_UPLOAD_FAILED", "Final executable not found for upload.");
  }

  const uploadedKeys: Record<string, string> = {};
  const hashes: Record<string, string> = {};

  // 1. Upload Final Standalone .exe
  const exeBytes = new Uint8Array(readFileSync(finalExe));
  const exeSha = await sha256Hex(exeBytes);
  const exeFileName = basename(finalExe);
  if (!exeFileName.toLowerCase().endsWith(".exe") || exeFileName.includes("..") || exeFileName.includes("/")) {
    throw new UploadError("ARTIFACT_UPLOAD_FAILED", `Invalid executable file name: ${exeFileName}`);
  }
  const exeKey = `${prefix}/${exeFileName}`;
  await r2Put(creds, exeKey, exeBytes, "application/octet-stream");
  uploadedKeys.executable = exeKey;
  hashes.executable = exeSha;
  console.log(`[Upload] Uploaded executable: ${exeKey} (${exeBytes.length} bytes, sha: ${exeSha})`);

  // 2. Upload preview.png
  const previewPng = join(wsDir, "artifacts", "preview.png");
  if (!existsSync(previewPng)) {
    throw new UploadError("ARTIFACT_UPLOAD_FAILED", "Required preview.png not found for upload.");
  }
  const pngBytes = new Uint8Array(readFileSync(previewPng));
  const pngSha = await sha256Hex(pngBytes);
  const previewKey = `${prefix}/preview.png`;
  await r2Put(creds, previewKey, pngBytes, "image/png");
  uploadedKeys.preview = previewKey;
  hashes.preview = pngSha;
  console.log(`[Upload] Uploaded preview: ${previewKey} (${pngBytes.length} bytes, sha: ${pngSha})`);

  // 3. Upload native-generation-result.json
  const genResultPath = join(wsDir, "artifacts", "native-generation-result.json");
  if (existsSync(genResultPath)) {
    const genBytes = new Uint8Array(readFileSync(genResultPath));
    const genSha = await sha256Hex(genBytes);
    const genKey = `${prefix}/native-generation-result.json`;
    await r2Put(creds, genKey, genBytes, "application/json");
    uploadedKeys.generationResult = genKey;
    hashes.generationResult = genSha;
    console.log(`[Upload] Uploaded native-generation-result.json: ${genKey}`);
  }

  // 4. Upload native-acceptance.json
  const acceptancePath = join(wsDir, "artifacts", "native-acceptance.json");
  if (existsSync(acceptancePath)) {
    const accBytes = new Uint8Array(readFileSync(acceptancePath));
    const accSha = await sha256Hex(accBytes);
    const accKey = `${prefix}/native-acceptance.json`;
    await r2Put(creds, accKey, accBytes, "application/json");
    uploadedKeys.acceptance = accKey;
    hashes.acceptance = accSha;
    console.log(`[Upload] Uploaded native-acceptance.json: ${accKey}`);
  }

  // 5. Upload Runtime Evidence Bundle (manifest, scenarios, screenshots)
  const evidenceDir = join(wsDir, "runtime-evidence");
  const manifestPath = join(evidenceDir, "manifest.json");
  let runtimeEvidenceManifestKey: string | undefined;
  let runtimeEvidenceManifestSha256: string | undefined;

  if (existsSync(manifestPath)) {
    const manifestBytes = new Uint8Array(readFileSync(manifestPath));
    const manifestSha = await sha256Hex(manifestBytes);
    const manifestKey = `${prefix}/runtime-evidence/manifest.json`;
    await r2Put(creds, manifestKey, manifestBytes, "application/json");
    uploadedKeys.runtimeEvidenceManifest = manifestKey;
    hashes.runtimeEvidenceManifest = manifestSha;
    runtimeEvidenceManifestKey = manifestKey;
    runtimeEvidenceManifestSha256 = manifestSha;
    console.log(`[Upload] Uploaded runtime-evidence/manifest.json: ${manifestKey} (sha: ${manifestSha})`);

    // Upload scenarios
    const scenariosDir = join(evidenceDir, "scenarios");
    if (existsSync(scenariosDir)) {
      for (const file of readdirSync(scenariosDir)) {
        if (file.endsWith(".json")) {
          const scnBytes = new Uint8Array(readFileSync(join(scenariosDir, file)));
          const scnKey = `${prefix}/runtime-evidence/scenarios/${file}`;
          await r2Put(creds, scnKey, scnBytes, "application/json");
        }
      }
    }

    // Upload screenshots
    const screenshotsDir = join(evidenceDir, "screenshots");
    if (existsSync(screenshotsDir)) {
      for (const file of readdirSync(screenshotsDir)) {
        if (file.endsWith(".png")) {
          const pngBytes = new Uint8Array(readFileSync(join(screenshotsDir, file)));
          const pngKey = `${prefix}/runtime-evidence/screenshots/${file}`;
          await r2Put(creds, pngKey, pngBytes, "image/png");
        }
      }
    }
  }

  // 6. Upload Visual Acceptance Report
  const visualReportPath = join(wsDir, "artifacts", "visual-acceptance.json");
  let visualAcceptanceManifestKey: string | undefined;
  let visualAcceptanceManifestSha256: string | undefined;

  if (existsSync(visualReportPath)) {
    const reportBytes = new Uint8Array(readFileSync(visualReportPath));
    const reportSha = await sha256Hex(reportBytes);
    const reportKey = `${prefix}/visual-acceptance/report.json`;
    await r2Put(creds, reportKey, reportBytes, "application/json");
    uploadedKeys.visualAcceptanceReport = reportKey;
    hashes.visualAcceptanceReport = reportSha;
    visualAcceptanceManifestKey = reportKey;
    visualAcceptanceManifestSha256 = reportSha;
    console.log(`[Upload] Uploaded visual-acceptance/report.json: ${reportKey} (sha: ${reportSha})`);
  }

  saveRunResult({
    artifactKey: exeKey,
    artifactSha256: exeSha,
    artifactSize: exeBytes.length,
    fileName: exeFileName,
    previewKey,
    previewSha256: pngSha,
    runtimeEvidenceManifestKey,
    runtimeEvidenceManifestSha256,
    visualAcceptanceManifestKey,
    visualAcceptanceManifestSha256,
    uploadedKeys,
    uploadedHashes: hashes,
  });

  return { uploadedKeys, hashes };
}

export class UploadError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "UploadError";
  }
}

if (import.meta.main) {
  const wsDir = loadRunResult().wsDir;
  try {
    await uploadArtifacts(wsDir);
  } catch (err) {
    const code = (err as { code?: string })?.code || "ARTIFACT_UPLOAD_FAILED";
    const msg = (err as Error)?.message ?? String(err);
    console.error(`[Upload] FAIL CLOSED: ${code} - ${msg}`);
    saveRunResult({ stepFailed: true, errorCode: code, errorMessage: msg });
    process.exit(1);
  }
}
