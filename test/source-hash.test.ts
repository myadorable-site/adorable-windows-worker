import { describe, expect, it } from "bun:test";
import {
  computeSourceBundleHash,
  extractProvenanceInputs,
  isVolatileArtifact,
  normalizeSourcePath,
  type GeneratedFile,
  type SourceBundleProvenanceInputs,
} from "../scripts/source-hash.ts";

describe("Worker Source Bundle Hash (Non-Circular Parity)", () => {
  const sampleFiles: GeneratedFile[] = [
    { relativePath: "package.json", content: '{"name":"test-app"}' },
    { relativePath: "app.tsx", content: "export default function App() { return null; }" },
  ];

  const standardProvenance: SourceBundleProvenanceInputs = {
    generationContractHash: "h-12345678abcdef01",
    generationContractVersion: "v0.9A",
    quickGuiRepository: "https://github.com/egoist/quickgui.git",
    quickGuiRevision: "0a5007a03be4a0ba08c7da27010f74699711255a",
    targetPlatform: "windows",
    targetArch: "x64",
  };

  it("1. identical files + identical non-self-referential provenance -> identical sourceBundleHash", () => {
    const hash1 = computeSourceBundleHash(sampleFiles, standardProvenance);
    const hash2 = computeSourceBundleHash([...sampleFiles].reverse(), standardProvenance);
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("2. generationContractHash mutation -> different sourceBundleHash", () => {
    const hash1 = computeSourceBundleHash(sampleFiles, standardProvenance);
    const hash2 = computeSourceBundleHash(sampleFiles, {
      ...standardProvenance,
      generationContractHash: "h-9999999999999999",
    });
    expect(hash1).not.toBe(hash2);
  });

  it("3. QuickGUI revision mutation -> different sourceBundleHash", () => {
    const hash1 = computeSourceBundleHash(sampleFiles, standardProvenance);
    const hash2 = computeSourceBundleHash(sampleFiles, {
      ...standardProvenance,
      quickGuiRevision: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    });
    expect(hash1).not.toBe(hash2);
  });

  it("4. target platform/arch mutation -> different sourceBundleHash", () => {
    const hash1 = computeSourceBundleHash(sampleFiles, standardProvenance);
    const hash2 = computeSourceBundleHash(sampleFiles, {
      ...standardProvenance,
      targetPlatform: "linux",
    });
    expect(hash1).not.toBe(hash2);
  });

  it("5. sourceBundleHash is explicitly not an input to its own computation", () => {
    const hashWithoutSelf = computeSourceBundleHash(sampleFiles, standardProvenance);
    const hashWithSelfInjected = computeSourceBundleHash(sampleFiles, {
      ...standardProvenance,
      sourceBundleHash: "injected-fake-hash-must-be-ignored",
    });
    expect(hashWithoutSelf).toBe(hashWithSelfInjected);
  });

  it("6. extracts only non-circular provenance inputs", () => {
    const metaWithEverything = {
      generationContractHash: "h-12345678abcdef01",
      generationContractVersion: "v0.9A",
      quickGuiRepository: "https://github.com/egoist/quickgui.git",
      quickGuiRevision: "0a5007a03be4a0ba08c7da27010f74699711255a",
      targetPlatform: "windows",
      targetArch: "x64",
      sourceBundleHash: "tampered-hash",
      randomField: 42,
    };

    const extracted = extractProvenanceInputs(metaWithEverything);
    expect(extracted).toBeDefined();
    expect((extracted as Record<string, unknown>).sourceBundleHash).toBeUndefined();
    expect((extracted as Record<string, unknown>).randomField).toBeUndefined();
    expect(extracted?.generationContractHash).toBe("h-12345678abcdef01");
  });

  it("7. excludes volatile artifacts and logs", () => {
    const filesWithVolatile: GeneratedFile[] = [
      ...sampleFiles,
      { relativePath: "dist/app.exe", content: "exe" },
      { relativePath: "build/temp.obj", content: "obj" },
      { relativePath: "app.log", content: "log" },
      { relativePath: "yarn.lock", content: "lock" },
    ];
    const baseHash = computeSourceBundleHash(sampleFiles, standardProvenance);
    const volatileHash = computeSourceBundleHash(filesWithVolatile, standardProvenance);
    expect(volatileHash).toBe(baseHash);
  });
});
