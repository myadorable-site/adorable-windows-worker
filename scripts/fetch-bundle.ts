/**
 * Step 1 — fetch validated source bundle from R2 and verify inputs, provenance, and canonical hash.
 * Fails closed on ANY mismatch:
 * - PROVENANCE_MISMATCH on input or metadata discrepancies
 * - SOURCE_HASH_MISMATCH on canonical hash discrepancy
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { readCreds, r2Get, saveRunResult } from "./r2.ts";
import {
  computeSourceBundleHash,
  extractProvenanceInputs,
  type GeneratedFile,
  type SourceBundleProvenanceInputs,
} from "./source-hash.ts";
import {
  PINNED_QUICKGUI_REVISION,
  PINNED_QUICKGUI_REVISION_FULL,
  isMatchingRevision,
} from "./verify-toolchain.ts";

export interface SourceBundlePayload {
  files: Array<{ path?: string; relativePath?: string; content: string }>;
  meta?: Record<string, unknown>;
}

export function validateInputContract(): {
  jobId: string;
  projectId: string;
  buildId: string;
  appId: string;
  sourceBundleKey: string;
  sourceBundleSha256: string;
  targetPlatform: string;
  targetArch: string;
  generationContractHash: string;
  quickguiRevision: string;
} {
  const targetPlatform = (process.env.ADORABLE_TARGET_PLATFORM ?? "windows").toLowerCase();
  const targetArch = (process.env.ADORABLE_TARGET_ARCH ?? "x64").toLowerCase();
  const generationContractHash = (process.env.ADORABLE_GENERATION_CONTRACT_HASH ?? "").trim();
  const quickguiRevision = (process.env.ADORABLE_QUICKGUI_REVISION ?? "").trim();
  const sourceBundleKey = (process.env.ADORABLE_SOURCE_BUNDLE_KEY ?? "").trim();
  const sourceBundleSha256 = (process.env.ADORABLE_SOURCE_BUNDLE_SHA256 ?? "").trim().toLowerCase();

  // Validate platform & arch
  if (targetPlatform !== "windows" || targetArch !== "x64") {
    throw new ProvenanceMismatchError(
      `Invalid target: expected windows/x64, got ${targetPlatform}/${targetArch}`,
    );
  }

  // Validate contract hash format: h-[0-9a-f]{16} or 64-char hex
  const validContractHash =
    /^h-[0-9a-f]{16}$/.test(generationContractHash) ||
    /^[0-9a-f]{64}$/.test(generationContractHash);
  if (!generationContractHash || !validContractHash) {
    throw new ProvenanceMismatchError(
      `Invalid generation_contract_hash: "${generationContractHash}". Expected h-[0-9a-f]{16} or 64-char hex.`,
    );
  }

  // Validate quickgui revision
  if (!isMatchingRevision(quickguiRevision)) {
    throw new ProvenanceMismatchError(
      `QuickGUI revision mismatch in workflow inputs: got "${quickguiRevision}", expected "${PINNED_QUICKGUI_REVISION}".`,
    );
  }

  if (!sourceBundleKey) {
    throw new Error("Source bundle key is missing.");
  }
  if (!/^[0-9a-f]{64}$/.test(sourceBundleSha256)) {
    throw new Error("Source bundle hash is malformed.");
  }

  return {
    jobId: process.env.ADORABLE_JOB_ID ?? "",
    projectId: process.env.ADORABLE_PROJECT_ID ?? "",
    buildId: process.env.ADORABLE_BUILD_ID ?? "",
    appId: process.env.ADORABLE_APP_ID ?? "",
    sourceBundleKey,
    sourceBundleSha256,
    targetPlatform,
    targetArch,
    generationContractHash,
    quickguiRevision,
  };
}

export class ProvenanceMismatchError extends Error {
  code = "PROVENANCE_MISMATCH";
  constructor(message: string) {
    super(message);
    this.name = "ProvenanceMismatchError";
  }
}

export class SourceHashMismatchError extends Error {
  code = "SOURCE_HASH_MISMATCH";
  constructor(message: string) {
    super(message);
    this.name = "SourceHashMismatchError";
  }
}

export async function fetchAndVerifySourceBundle(): Promise<{
  filesStaged: number;
  computedHash: string;
  provenance: SourceBundleProvenanceInputs;
}> {
  const inputs = validateInputContract();

  const creds = readCreds();
  const bytes = await r2Get(creds, inputs.sourceBundleKey);
  if (!bytes) {
    throw new Error("Source bundle not found in object storage.");
  }

  const text = new TextDecoder().decode(bytes);
  let bundle: SourceBundlePayload;
  try {
    bundle = JSON.parse(text) as SourceBundlePayload;
  } catch (err) {
    throw new Error(`Failed to parse source bundle JSON: ${(err as Error)?.message ?? err}`);
  }

  if (!bundle || !Array.isArray(bundle.files) || bundle.files.length === 0) {
    throw new Error("Source bundle has no files.");
  }

  const meta = bundle.meta ?? {};

  // 1. Verify SourceBundle.meta fields
  const metaContractHash = String(meta.generationContractHash ?? "");
  const metaQuickGuiRev = String(meta.quickGuiRevision ?? "");
  const metaPlatform = String(meta.targetPlatform ?? "");
  const metaArch = String(meta.targetArch ?? "");
  const metaSourceHash = String(meta.sourceBundleHash ?? "").toLowerCase();

  if (metaContractHash !== inputs.generationContractHash) {
    throw new ProvenanceMismatchError(
      `generationContractHash mismatch: meta has "${metaContractHash}", workflow input has "${inputs.generationContractHash}"`,
    );
  }

  if (!isMatchingRevision(metaQuickGuiRev)) {
    throw new ProvenanceMismatchError(
      `quickGuiRevision mismatch: meta has "${metaQuickGuiRev}", expected "${PINNED_QUICKGUI_REVISION}"`,
    );
  }

  if (metaPlatform !== "windows" || metaArch !== "x64") {
    throw new ProvenanceMismatchError(
      `Target platform/arch mismatch: meta has "${metaPlatform}/${metaArch}", expected "windows/x64"`,
    );
  }

  // 2. Canonical Source Bundle Hash Verification (Exact Non-Circular Algorithm)
  const genFiles: GeneratedFile[] = bundle.files.map((f) => ({
    relativePath: f.relativePath ?? f.path,
    content: f.content,
  }));

  const provenanceInputs: SourceBundleProvenanceInputs = {
    generationContractHash: inputs.generationContractHash,
    generationContractVersion: String(meta.generationContractVersion ?? "v0.9A"),
    quickGuiRepository: String(meta.quickGuiRepository ?? "https://github.com/egoist/quickgui.git"),
    quickGuiRevision: metaQuickGuiRev || PINNED_QUICKGUI_REVISION_FULL,
    targetPlatform: inputs.targetPlatform,
    targetArch: inputs.targetArch,
  };

  const computedHash = computeSourceBundleHash(genFiles, provenanceInputs).toLowerCase();

  if (computedHash !== inputs.sourceBundleSha256) {
    throw new SourceHashMismatchError(
      `Source bundle hash mismatch against workflow input: computed "${computedHash}", workflow input has "${inputs.sourceBundleSha256}"`,
    );
  }

  if (metaSourceHash && computedHash !== metaSourceHash) {
    throw new SourceHashMismatchError(
      `Source bundle hash mismatch against metadata: computed "${computedHash}", metadata has "${metaSourceHash}"`,
    );
  }

  // 3. Stage verified source files
  const wsDir = join(process.env.RUNNER_TEMP ?? "", "adorable-ws");
  let count = 0;
  for (const f of bundle.files) {
    const rawPath = f.relativePath ?? f.path;
    if (!rawPath || typeof rawPath !== "string" || typeof f.content !== "string") {
      throw new Error("Source bundle entry malformed.");
    }
    const rel = rawPath.replace(/\\/g, "/").replace(/^\/+/, "");
    if (!rel || rel.includes("..") || rel.startsWith("/") || /^[A-Za-z]:/.test(rel) || rel.length > 512) {
      throw new Error("Source bundle path rejected.");
    }
    if (f.content.length > 500_000) {
      throw new Error("Source bundle entry too large.");
    }
    const dest = resolve(wsDir, rel);
    if (dest !== wsDir && !dest.startsWith(wsDir + sep)) {
      throw new Error("Source bundle escape rejected.");
    }
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.content, "utf8");
    count++;
  }

  // Stage RuntimeEvidenceContract if present in metadata or from canonical fallback
  let runtimeEvidenceContract = meta.runtimeEvidenceContract;
  if (!runtimeEvidenceContract && inputs.generationContractHash === "h-e44a337649b66028") {
    const canonicalPath = join(import.meta.dir, "canonical-evidence-contract.json");
    if (existsSync(canonicalPath)) {
      try {
        runtimeEvidenceContract = JSON.parse(readFileSync(canonicalPath, "utf8"));
        console.log(`[Fetch] Loaded canonical RuntimeEvidenceContract for ${inputs.generationContractHash}`);
      } catch (err) {
        console.warn(`[Fetch] Failed to parse canonical contract: ${err}`);
      }
    }
  }

  if (runtimeEvidenceContract && typeof runtimeEvidenceContract === "object") {
    const evidenceContractPath = join(wsDir, "runtime-evidence-contract.json");
    writeFileSync(evidenceContractPath, JSON.stringify(runtimeEvidenceContract, null, 2), "utf8");
    console.log(`[Fetch] Staged RuntimeEvidenceContract at ${evidenceContractPath}`);
  }

  saveRunResult({
    filesStaged: count,
    sourceVerified: true,
    computedSourceBundleHash: computedHash,
    generationContractHash: inputs.generationContractHash,
    quickguiRevision: inputs.quickguiRevision,
    targetPlatform: inputs.targetPlatform,
    targetArch: inputs.targetArch,
    provenanceInputs,
    runtimeEvidenceContract,
  });

  console.log(`[Fetch] Staged ${count} verified source files. Canonical hash: ${computedHash}`);
  return { filesStaged: count, computedHash, provenance: provenanceInputs };
}

if (import.meta.main) {
  try {
    await fetchAndVerifySourceBundle();
  } catch (err) {
    const code = (err as { code?: string })?.code || "FETCH_FAILED";
    const msg = (err as Error)?.message ?? String(err);
    console.error(`[Fetch] FAIL CLOSED (${code}): ${msg}`);
    saveRunResult({
      stepFailed: true,
      errorCode: code,
      errorMessage: msg,
    });
    process.exit(1);
  }
}
