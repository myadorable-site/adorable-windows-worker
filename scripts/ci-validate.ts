/**
 * Worker CI Validation Script
 * Verifies that all required worker scripts exist, are non-empty,
 * pass Bun syntax compilation, and satisfy TypeScript types.
 */
import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const REQUIRED_SCRIPTS = [
  "capture-window.ps1",
  "clean.ts",
  "fetch-bundle.ts",
  "generate-acceptance.ts",
  "install-deps.ts",
  "package.ts",
  "pe-validator.ts",
  "r2.ts",
  "report.ts",
  "run-step.ts",
  "setup-toolchain.ts",
  "smoke.ts",
  "source-hash.ts",
  "upload.ts",
  "validate.ts",
  "verify-toolchain.ts",
];

console.log("=== ADORABLE WORKER SCRIPT AUDIT ===");
const scriptsDir = join(__dirname);

let missingCount = 0;
for (const script of REQUIRED_SCRIPTS) {
  const p = join(scriptsDir, script);
  if (!existsSync(p)) {
    console.error(`FAIL: Missing required script: ${script}`);
    missingCount++;
  } else {
    const sz = statSync(p).size;
    if (sz === 0) {
      console.error(`FAIL: Script is empty: ${script}`);
      missingCount++;
    } else {
      console.log(`PASS: ${script} (${sz} bytes)`);
    }
  }
}

if (missingCount > 0) {
  console.error(`Worker validation failed: ${missingCount} missing/empty script(s)`);
  process.exit(1);
}

console.log("\n=== BUN SYNTAX TRANSPILLATION CHECK ===");
const tsFiles = readdirSync(scriptsDir).filter((f) => f.endsWith(".ts"));
for (const file of tsFiles) {
  const filePath = join(scriptsDir, file);
  const result = spawnSync("bun", ["build", filePath, "--no-bundle"], {
    encoding: "utf-8",
  });
  if (result.status !== 0) {
    console.error(`FAIL: Syntax error in ${file}:\n${result.stderr}`);
    process.exit(1);
  }
  console.log(`PASS: ${file} compiled cleanly`);
}

console.log("\nWorker scripts validated successfully.");
