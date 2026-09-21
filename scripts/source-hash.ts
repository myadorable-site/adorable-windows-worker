import { createHash } from "node:crypto";

export interface GeneratedFile {
  relativePath?: string;
  path?: string;
  content: string;
}

export interface SourceBundleProvenanceInputs {
  generationContractHash?: string;
  generationContractVersion?: string;
  quickGuiRepository?: string;
  quickGuiRevision?: string;
  targetPlatform?: string;
  targetArch?: string;
  /**
   * sourceBundleHash is explicitly not an input to its own computation.
   * If present on passed metadata, it is strictly ignored during hash computation.
   */
  sourceBundleHash?: unknown;
}

export function normalizeSourcePath(filePath: string): string {
  return filePath
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/^\//, "")
    .trim();
}

export function isVolatileArtifact(normalizedPath: string): boolean {
  const lower = normalizedPath.toLowerCase();

  // Directory exclusions
  if (
    lower.startsWith("dist/") ||
    lower.includes("/dist/") ||
    lower.startsWith("build/") ||
    lower.includes("/build/") ||
    lower.startsWith("node_modules/") ||
    lower.includes("/node_modules/") ||
    lower.startsWith(".git/") ||
    lower.includes("/.git/") ||
    lower.startsWith("artifacts/") ||
    lower.includes("/artifacts/") ||
    lower.startsWith(".adorable/") ||
    lower.includes("/.adorable/") ||
    lower.startsWith(".tmp") ||
    lower.includes("/.tmp")
  ) {
    return true;
  }

  // File extension exclusions
  if (
    lower.endsWith(".log") ||
    lower.endsWith(".tmp") ||
    lower.endsWith(".temp") ||
    lower.endsWith(".lock")
  ) {
    return true;
  }

  return false;
}

/**
 * Computes canonical SHA-256 hash of a generated source bundle using the exact backend-compatible algorithm.
 *
 * CRITICAL ARCHITECTURAL INVARIANT:
 * "sourceBundleHash is not an input to its own computation."
 */
export function computeSourceBundleHash(
  files: GeneratedFile[],
  provenance?: SourceBundleProvenanceInputs,
): string {
  const hasher = createHash("sha256");

  // 1. Sort files lexicographically by normalized relative path
  const sortedFiles = [...files].sort((a, b) => {
    const na = normalizeSourcePath(a.relativePath ?? a.path ?? "");
    const nb = normalizeSourcePath(b.relativePath ?? b.path ?? "");
    return na.localeCompare(nb);
  });

  // 2. Hash source files (ignoring volatile artifacts and logs)
  for (const file of sortedFiles) {
    const normPath = normalizeSourcePath(file.relativePath ?? file.path ?? "");
    if (isVolatileArtifact(normPath)) continue;

    const contentHash = createHash("sha256").update(file.content, "utf8").digest("hex");
    hasher.update(`FILE:${normPath}:${contentHash}\n`, "utf8");
  }

  // 3. Hash non-circular provenance fields strictly (omitting sourceBundleHash)
  if (provenance) {
    if (provenance.generationContractHash) {
      hasher.update(`META:generationContractHash:${provenance.generationContractHash}\n`, "utf8");
    }
    if (provenance.generationContractVersion) {
      hasher.update(`META:generationContractVersion:${provenance.generationContractVersion}\n`, "utf8");
    }
    if (provenance.quickGuiRepository) {
      hasher.update(`META:quickGuiRepository:${provenance.quickGuiRepository}\n`, "utf8");
    }
    if (provenance.quickGuiRevision) {
      hasher.update(`META:quickGuiRevision:${provenance.quickGuiRevision}\n`, "utf8");
    }
    if (provenance.targetPlatform) {
      hasher.update(`META:targetPlatform:${provenance.targetPlatform}\n`, "utf8");
    }
    if (provenance.targetArch) {
      hasher.update(`META:targetArch:${provenance.targetArch}\n`, "utf8");
    }
  }

  return hasher.digest("hex");
}

export function extractProvenanceInputs(
  meta: Record<string, unknown> | undefined,
): SourceBundleProvenanceInputs | undefined {
  if (!meta) return undefined;
  const result: SourceBundleProvenanceInputs = {};
  if (typeof meta.generationContractHash === "string" && meta.generationContractHash) {
    result.generationContractHash = meta.generationContractHash;
  }
  if (typeof meta.generationContractVersion === "string" && meta.generationContractVersion) {
    result.generationContractVersion = meta.generationContractVersion;
  }
  if (typeof meta.quickGuiRepository === "string" && meta.quickGuiRepository) {
    result.quickGuiRepository = meta.quickGuiRepository;
  }
  if (typeof meta.quickGuiRevision === "string" && meta.quickGuiRevision) {
    result.quickGuiRevision = meta.quickGuiRevision;
  }
  if (typeof meta.targetPlatform === "string" && meta.targetPlatform) {
    result.targetPlatform = meta.targetPlatform;
  }
  if (typeof meta.targetArch === "string" && meta.targetArch) {
    result.targetArch = meta.targetArch;
  }
  return Object.keys(result).length > 0 ? result : undefined;
}
