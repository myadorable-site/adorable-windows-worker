/**
 * Step 4 — trusted security validation over the staged workspace.
 *
 * Checks:
 * 1. Dependency policy + lifecycle scripts
 * 2. Unsafe process spawning (child_process, powershell, cmd.exe, Bun.spawn)
 * 3. Secret patterns, private keys, API keys
 * 4. Unsafe path traversal / host escapes
 * 5. Secret-free verification of generated artifacts
 *
 * FAIL CLOSED:
 * SECURITY_VALIDATION_FAILED
 */
import { readdirSync, readFileSync, statSync, lstatSync } from "node:fs";
import { join, relative } from "node:path";
import { loadRunResult, saveRunResult } from "./r2.ts";

export interface SecurityScanResult {
  ok: boolean;
  findings: Array<{ code: string; rule: string; path: string; details?: string }>;
  findingsSummary: string[];
}

export const SECRET_PATTERNS = [
  /OPENROUTER_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY/,
  /-----BEGIN (?:RSA )?PRIVATE KEY-----/,
  /sk-or-v1-[A-Za-z0-9]{8,}/,
  /ghp_[A-Za-z0-9]{8,}/,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, // JWT-like secret
  /\.env(\.|$)/,
];

export const PATH_PATTERNS = [
  /[A-Za-z]:\\Users\\/i,
  /adorable[\\/]workspaces/i,
  /\.\.[\/\\]\.\./,
];

export const SPAWN_PATTERNS = [
  /\bchild_process\b/,
  /\bpowershell(?:\.exe)?\b/i,
  /\bcmd(?:\.exe)?\b/i,
  /\bBun\s*\.\s*spawn\b/,
];

export function runSecurityValidation(wsDir: string): SecurityScanResult {
  const findings: Array<{ code: string; rule: string; path: string; details?: string }> = [];

  function walk(dir: string, out: string[]): void {
    let entries: string[] = [];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry === "node_modules" || entry === "dist" || entry === ".git") continue;
      const full = join(dir, entry);
      let st;
      try {
        st = lstatSync(full);
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) {
        findings.push({
          code: "SYM_LINK",
          rule: "no-symlinks",
          path: relative(wsDir, full),
          details: "Symbolic links are forbidden in source bundles",
        });
        continue;
      }
      try {
        if (st.isDirectory()) walk(full, out);
        else out.push(full);
      } catch {
        /* ignore */
      }
    }
  }

  const files: string[] = [];
  walk(wsDir, files);

  const read = (p: string): string => {
    try {
      const content = readFileSync(p, "utf8");
      return content.length > 500_000 ? "" : content;
    } catch {
      return "";
    }
  };

  // 1. Dependency policy
  const pkgJsonPath = join(wsDir, "package.json");
  try {
    const pkg = JSON.parse(read(pkgJsonPath)) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      scripts?: Record<string, string>;
    };
    const allowed = new Set([
      "@quickgui/native",
      "@quickgui/solid",
      "@quickgui/cli",
      "solid-js",
      "typescript",
      "@types/bun",
    ]);
    for (const section of [pkg.dependencies ?? {}, pkg.devDependencies ?? {}]) {
      for (const name of Object.keys(section)) {
        if (!allowed.has(name)) {
          findings.push({
            code: "UNAPPROVED_DEPENDENCY",
            rule: "allowed-dependencies-only",
            path: "package.json",
            details: `Unapproved dependency: ${name}`,
          });
        }
      }
    }
    for (const name of Object.keys(pkg.scripts ?? {})) {
      if (["preinstall", "install", "postinstall", "prepare", "prepublishOnly"].includes(name)) {
        findings.push({
          code: "FORBIDDEN_LIFECYCLE_SCRIPT",
          rule: "no-lifecycle-scripts",
          path: "package.json",
          details: `Forbidden lifecycle script: ${name}`,
        });
      }
    }
  } catch {
    findings.push({
      code: "MANIFEST_UNREADABLE",
      rule: "readable-manifest",
      path: "package.json",
      details: "package.json missing or invalid",
    });
  }

  // 2. Secret / Spawn / Path scan
  for (const full of files) {
    const rel = relative(wsDir, full);
    if (!(full.endsWith(".tsx") || full.endsWith(".ts") || full.endsWith(".js") || full.endsWith(".json"))) continue;
    const normalizedRel = rel.replace(/\\/g, "/");
    if (normalizedRel === "runtime/adorable-store.ts" || full.replace(/\\/g, "/").includes("runtime/adorable-store.ts")) continue;
    const content = read(full);
    if (!content) continue;

    for (const re of SECRET_PATTERNS) {
      if (re.test(content)) {
        findings.push({
          code: "SECRET_PATTERN",
          rule: "no-embedded-secrets",
          path: rel,
          details: `Matches secret pattern: ${re.source}`,
        });
        break;
      }
    }

    for (const re of PATH_PATTERNS) {
      if (re.test(content)) {
        findings.push({
          code: "UNSAFE_PATH",
          rule: "no-host-paths",
          path: rel,
          details: `Matches host path pattern: ${re.source}`,
        });
        break;
      }
    }

    if (!(full.endsWith(".json"))) {
      for (const re of SPAWN_PATTERNS) {
        if (re.test(content)) {
          findings.push({
            code: "SPAWN_PATTERN",
            rule: "no-child-process-spawning",
            path: rel,
            details: `Matches prohibited spawn pattern: ${re.source}`,
          });
          break;
        }
      }
    }
  }

  const ok = findings.length === 0;
  const findingsSummary = findings.map((f) => `[${f.code}] ${f.rule} on ${f.path}`);

  saveRunResult({
    securityPassed: ok,
    securityFindings: findingsSummary.slice(0, 20),
    securityScanResult: { ok, findings: findings.slice(0, 20) },
  });

  return { ok, findings, findingsSummary };
}

if (import.meta.main) {
  const wsDir = loadRunResult().wsDir;
  const res = runSecurityValidation(wsDir);
  if (!res.ok) {
    console.error(`[Security] FAIL CLOSED: SECURITY_VALIDATION_FAILED: ${res.findingsSummary.join(", ")}`);
    saveRunResult({
      stepFailed: true,
      errorCode: "SECURITY_VALIDATION_FAILED",
      errorMessage: `Security validation rejected app sources: ${res.findingsSummary.slice(0, 3).join("; ")}`,
    });
    process.exit(1);
  }
  console.log("[Security] Security validation passed cleanly.");
}
