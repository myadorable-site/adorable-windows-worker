/**
 * Step 3b — package the built QuickGUI Windows executable into a truly standalone,
 * self-contained .exe that launches standalone without companion DLLs or dev tools.
 *
 * QuickGUI outputs:
 *   dist/windows-x64/<AppName>.exe
 *   dist/windows-x64/quickgui_host.dll
 *   dist/windows-x64/<AppName>.exe.manifest
 *
 * Running <AppName>.exe directly outside its dist directory fails because it requires
 * quickgui_host.dll. This step embeds quickgui_host.dll and the payload application into
 * a single self-extracting runner using Windows built-in csc.exe, replacing the loose .exe
 * with a self-contained portable executable.
 *
 * MANDATORY v0.9B REQUIREMENT:
 * Re-runs PE validation on the FINAL packaged executable. The artifact uploaded to R2
 * MUST be the same final executable that passed final PE validation and will be launched.
 */
import { existsSync, readdirSync, statSync, mkdirSync, copyFileSync, rmSync, writeFileSync, unlinkSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { loadRunResult, saveRunResult } from "./r2.ts";
import { validateWindowsPe, type PeValidationResult } from "./pe-validator.ts";

export function findExe(dir: string): string | null {
  let entries: string[] = [];
  try {
    entries = readdirSync(dir);
  } catch {
    return null;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let isDir = false;
    try {
      isDir = statSync(full).isDirectory();
    } catch {
      continue;
    }
    if (isDir) {
      const nested = findExe(full);
      if (nested) return nested;
    } else if (entry.toLowerCase().endsWith(".exe") && !entry.toLowerCase().endsWith(".payload.exe")) {
      return full;
    }
  }
  return null;
}

export function packageStandaloneWindows(wsDir: string): {
  finalExe: string;
  finalPeValidation: PeValidationResult;
} | null {
  const distDir = join(wsDir, "dist");
  if (!existsSync(distDir)) return null;

  const mainExe = findExe(distDir);
  if (!mainExe || !existsSync(mainExe)) return null;

  const winDir = dirname(mainExe);
  const dllPath = join(winDir, "quickgui_host.dll");

  let finalExe = mainExe;

  if (existsSync(dllPath)) {
    const appBaseName = basename(mainExe, ".exe");
    const tempStaging = join(wsDir, `.package-staging-${Date.now()}`);
    const payloadZip = join(wsDir, `.payload-${Date.now()}.zip`);
    const launcherCs = join(wsDir, `.launcher-${Date.now()}.cs`);
    const launcherExe = join(wsDir, `.launcher-${Date.now()}.exe`);

    try {
      mkdirSync(tempStaging, { recursive: true });

      // Stage payload: main binary as app_payload.exe, plus quickgui_host.dll and other assets
      copyFileSync(mainExe, join(tempStaging, "app_payload.exe"));
      copyFileSync(dllPath, join(tempStaging, "quickgui_host.dll"));

      // Copy any fonts or resources directory if present
      const fontsDir = join(winDir, "fonts");
      if (existsSync(fontsDir)) {
        copyDirRecursive(fontsDir, join(tempStaging, "fonts"));
      }
      const resourcesDir = join(winDir, "resources");
      if (existsSync(resourcesDir)) {
        copyDirRecursive(resourcesDir, join(tempStaging, "resources"));
      }

      // Create zip archive using tar.exe or PowerShell Compress-Archive
      let zipSuccess = false;
      try {
        const tarRes = Bun.spawnSync(["tar.exe", "-a", "-c", "-f", payloadZip, "-C", tempStaging, "."], {
          stdin: "ignore",
          stdout: "pipe",
          stderr: "pipe",
        });
        if (tarRes.exitCode === 0 && existsSync(payloadZip) && statSync(payloadZip).size > 0) {
          zipSuccess = true;
        }
      } catch {
        /* fallback */
      }

      if (!zipSuccess) {
        const psRes = Bun.spawnSync(
          [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            `Compress-Archive -Path "${tempStaging}\\*" -DestinationPath "${payloadZip}" -Force`,
          ],
          { stdin: "ignore", stdout: "pipe", stderr: "pipe" },
        );
        if (psRes.exitCode !== 0 || !existsSync(payloadZip) || statSync(payloadZip).size === 0) {
          throw new PackagingError("PACKAGING_FAILED", "Failed to create payload zip for standalone packaging");
        }
      }

      // Write launcher C# source code
      const csCode = `using System;
using System.IO;
using System.IO.Compression;
using System.Diagnostics;
using System.Reflection;

namespace AdorableLauncher
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            try
            {
                string appName = ${JSON.stringify(appBaseName)};
                string payloadExe = "app_payload.exe";

                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrEmpty(localAppData))
                {
                    localAppData = Environment.GetEnvironmentVariable("TEMP") ?? Path.GetTempPath();
                }
                string targetDir = Path.Combine(localAppData, "Adorable", "Apps", appName);
                if (!Directory.Exists(targetDir))
                {
                    Directory.CreateDirectory(targetDir);
                }

                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
                {
                    if (stream != null)
                    {
                        using (var archive = new ZipArchive(stream))
                        {
                            foreach (var entry in archive.Entries)
                            {
                                if (string.IsNullOrEmpty(entry.Name)) continue;
                                string destPath = Path.Combine(targetDir, entry.FullName);
                                string entryDir = Path.GetDirectoryName(destPath);
                                if (!Directory.Exists(entryDir)) Directory.CreateDirectory(entryDir);

                                bool shouldExtract = !File.Exists(destPath);
                                if (!shouldExtract)
                                {
                                    var fi = new FileInfo(destPath);
                                    if (fi.Length != entry.Length)
                                    {
                                        shouldExtract = true;
                                    }
                                }

                                if (shouldExtract)
                                {
                                    entry.ExtractToFile(destPath, true);
                                }
                            }
                        }
                    }
                }

                string mainExe = Path.Combine(targetDir, payloadExe);
                if (!File.Exists(mainExe))
                {
                    return 1;
                }

                var psi = new ProcessStartInfo
                {
                    FileName = mainExe,
                    WorkingDirectory = targetDir,
                    UseShellExecute = false
                };

                if (args != null && args.Length > 0)
                {
                    var escaped = new string[args.Length];
                    for (int i = 0; i < args.Length; i++)
                    {
                        string a = args[i] ?? "";
                        if (a.Contains(" ") || a.Contains("\\""))
                        {
                            escaped[i] = "\\"" + a.Replace("\\"", "\\\\\\"") + "\\"";
                        }
                        else
                        {
                            escaped[i] = a;
                        }
                    }
                    psi.Arguments = string.Join(" ", escaped);
                }

                using (var proc = Process.Start(psi))
                {
                    if (proc == null) return 1;
                    proc.WaitForExit();
                    return proc.ExitCode;
                }
            }
            catch
            {
                return 1;
            }
        }
    }
}
`;
      writeFileSync(launcherCs, csCode, "utf8");

      // Find csc.exe
      const cscCandidates = [
        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe",
      ];
      let cscPath: string | undefined;
      for (const cand of cscCandidates) {
        if (existsSync(cand)) {
          cscPath = cand;
          break;
        }
      }
      if (!cscPath) {
        throw new PackagingError("PACKAGING_FAILED", "csc.exe not found; cannot package standalone launcher.");
      }

      const cscArgs = [
        cscPath,
        "/target:winexe",
        "/platform:x64",
        "/optimize+",
        "/r:System.IO.Compression.dll",
        "/r:System.IO.Compression.FileSystem.dll",
        `/resource:${payloadZip},payload.zip`,
        `/out:${launcherExe}`,
      ];

      const manifestCandidate = `${mainExe}.manifest`;
      if (existsSync(manifestCandidate)) {
        cscArgs.push(`/win32manifest:${manifestCandidate}`);
      }

      const icoCandidate = join(winDir, `${appBaseName}.ico`);
      if (existsSync(icoCandidate)) {
        cscArgs.push(`/win32icon:${icoCandidate}`);
      }

      cscArgs.push(launcherCs);

      const cscRes = Bun.spawnSync(cscArgs, { stdin: "ignore", stdout: "pipe", stderr: "pipe" });
      if (cscRes.exitCode !== 0 || !existsSync(launcherExe)) {
        const errText = new TextDecoder().decode(cscRes.stderr);
        throw new PackagingError("PACKAGING_FAILED", `csc.exe compilation failed: ${errText}`);
      }

      // Replace mainExe with the standalone launcher
      copyFileSync(launcherExe, mainExe);

      // Clean up loose quickgui_host.dll from dist so dist contains only the self-contained executable
      try {
        unlinkSync(dllPath);
      } catch {
        /* ignore */
      }

      finalExe = mainExe;
      console.log(`[Package] Packaged standalone self-contained executable: ${finalExe} (${statSync(finalExe).size} bytes).`);
    } finally {
      try { rmSync(tempStaging, { recursive: true, force: true }); } catch { /* ignore */ }
      try { unlinkSync(payloadZip); } catch { /* ignore */ }
      try { unlinkSync(launcherCs); } catch { /* ignore */ }
      try { unlinkSync(launcherExe); } catch { /* ignore */ }
    }
  }

  // MANDATORY: Re-run PE validation on the final executable candidate
  const peRes = validateWindowsPe(finalExe);
  if (!peRes.valid) {
    throw new PackagingError("CORRUPT_PE", `Final standalone executable PE validation failed: ${peRes.error}`);
  }

  saveRunResult({
    finalExe,
    finalPeValidation: peRes,
    artifactSha256: peRes.sha256,
    artifactSize: peRes.fileSize,
  });

  return { finalExe, finalPeValidation: peRes };
}

function copyDirRecursive(src: string, dest: string): void {
  mkdirSync(dest, { recursive: true });
  for (const entry of readdirSync(src)) {
    const s = join(src, entry);
    const d = join(dest, entry);
    if (statSync(s).isDirectory()) {
      copyDirRecursive(s, d);
    } else {
      copyFileSync(s, d);
    }
  }
}

export class PackagingError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "PackagingError";
  }
}

// When run directly as CLI step:
if (import.meta.main) {
  const wsDir = loadRunResult().wsDir;
  try {
    const res = packageStandaloneWindows(wsDir);
    if (res) {
      console.log(`Standalone packaging completed and verified for ${res.finalExe}.`);
    } else {
      throw new PackagingError("PACKAGING_FAILED", "No executable found in workspace dist to package.");
    }
  } catch (err) {
    const code = (err as { code?: string })?.code || "PACKAGING_FAILED";
    const msg = (err as Error)?.message ?? String(err);
    console.error(`[Package] FAIL CLOSED: ${code} - ${msg}`);
    saveRunResult({ stepFailed: true, errorCode: code, errorMessage: msg });
    process.exit(1);
  }
}
