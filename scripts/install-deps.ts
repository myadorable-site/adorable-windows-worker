/**
 * Step 2 — install dependencies safely with --ignore-scripts.
 *
 * Chooses strategy:
 * A. If bun.lock is present: bun install --ignore-scripts --frozen-lockfile
 * B. If bun.lock is absent: documented bun install --ignore-scripts, recording resolved dependency versions
 *
 * Fails closed on any error with DEPENDENCY_INSTALL_FAILED.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { loadRunResult, saveRunResult } from "./r2.ts";

export interface ResolvedDependencyProvenance {
  strategy: "frozen-lockfile" | "non-frozen-recorded";
  lockfilePresent: boolean;
  installedPackages: Record<string, string>;
}

export function installDependencies(wsDir: string): ResolvedDependencyProvenance {
  const lockfilePath = join(wsDir, "bun.lock");
  const lockfilePresent = existsSync(lockfilePath);

  const args = ["install", "--ignore-scripts"];
  let strategy: "frozen-lockfile" | "non-frozen-recorded";

  if (lockfilePresent) {
    args.push("--frozen-lockfile");
    strategy = "frozen-lockfile";
    console.log("[Install] Lockfile bun.lock found: using --frozen-lockfile mode.");
  } else {
    strategy = "non-frozen-recorded";
    console.log("[Install] No lockfile found in source bundle: using non-frozen install and recording resolved dependencies.");
  }

  const res = spawnSync("bun", args, {
    cwd: wsDir,
    encoding: "utf8",
    env: { ...process.env },
  });

  if (res.status !== 0) {
    const errText = (res.stderr || res.stdout || "Unknown error").slice(0, 500);
    throw new DependencyInstallError(`Dependency installation failed (exit code ${res.status}): ${errText}`);
  }

  // Inspect resolved packages in node_modules
  const installedPackages: Record<string, string> = {};
  const nodeModulesDir = join(wsDir, "node_modules");

  const scanDir = (dir: string, prefix = "") => {
    if (!existsSync(dir)) return;
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (entry.name.startsWith("@")) {
            scanDir(join(dir, entry.name), `${entry.name}/`);
          } else {
            const pkgJsonPath = join(dir, entry.name, "package.json");
            if (existsSync(pkgJsonPath)) {
              try {
                const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8")) as { name?: string; version?: string };
                if (pkg.name && pkg.version) {
                  installedPackages[pkg.name] = pkg.version;
                }
              } catch {
                /* ignore */
              }
            }
          }
        }
      }
    } catch {
      /* ignore */
    }
  };

  scanDir(nodeModulesDir);

  const depResult: ResolvedDependencyProvenance = {
    strategy,
    lockfilePresent,
    installedPackages,
  };

  saveRunResult({ dependencyProvenance: depResult });
  console.log(`[Install] Successfully resolved ${Object.keys(installedPackages).length} dependencies.`);
  return depResult;
}

export class DependencyInstallError extends Error {
  code = "DEPENDENCY_INSTALL_FAILED";
  constructor(message: string) {
    super(message);
    this.name = "DependencyInstallError";
  }
}

if (import.meta.main) {
  const wsDir = loadRunResult().wsDir;
  try {
    installDependencies(wsDir);
  } catch (err) {
    const code = (err as { code?: string })?.code || "DEPENDENCY_INSTALL_FAILED";
    const msg = (err as Error)?.message ?? String(err);
    console.error(`[Install] FAIL CLOSED: ${code} - ${msg}`);
    saveRunResult({
      stepFailed: true,
      errorCode: code,
      errorMessage: msg,
    });
    process.exit(1);
  }
}
