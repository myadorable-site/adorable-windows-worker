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
import { existsSync, readFileSync } from "node:fs";
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

  saveRunResult({
    artifactKey: exeKey,
    artifactSha256: exeSha,
    artifactSize: exeBytes.length,
    fileName: exeFileName,
    previewKey,
    previewSha256: pngSha,
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
