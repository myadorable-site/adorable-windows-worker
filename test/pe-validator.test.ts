import { describe, expect, it, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { validateWindowsPe, MINIMUM_PE_SIZE_BYTES } from "../scripts/pe-validator.ts";

const TEST_DIR = join(import.meta.dir, ".tmp-pe-" + Date.now());

function createSyntheticPe(options?: {
  size?: number;
  magic?: number;
  e_lfanew?: number;
  peSig?: number[];
  machine?: number;
  numberOfSections?: number;
}): Buffer {
  const size = options?.size ?? 1024 * 1024 + 1024;
  const buf = Buffer.alloc(size, 0);

  buf.writeUInt16LE(options?.magic ?? 0x5a4d, 0); // "MZ"
  const peOffset = options?.e_lfanew ?? 0x80;
  buf.writeUInt32LE(peOffset, 0x3c);

  if (peOffset + 4 <= buf.length) {
    const sig = options?.peSig ?? [0x50, 0x45, 0x00, 0x00];
    for (let i = 0; i < 4; i++) buf[peOffset + i] = sig[i];
  }

  const coff = peOffset + 4;
  if (coff + 24 <= buf.length) {
    buf.writeUInt16LE(options?.machine ?? 0x8664, coff);
    const numSections = options?.numberOfSections ?? 1;
    buf.writeUInt16LE(numSections, coff + 2);
    const optHeaderSize = 240;
    buf.writeUInt16LE(optHeaderSize, coff + 16);

    const opt = coff + 20;
    if (opt + 2 <= buf.length) {
      buf.writeUInt16LE(0x020b, opt);
    }

    const sectionTable = opt + optHeaderSize;
    for (let s = 0; s < numSections; s++) {
      const sOffset = sectionTable + s * 40;
      if (sOffset + 40 <= buf.length) {
        buf.write(".text", sOffset, "utf8");
        buf.writeUInt32LE(0x1000, sOffset + 8);
        buf.writeUInt32LE(0x1000, sOffset + 12);
        buf.writeUInt32LE(512, sOffset + 16);
        buf.writeUInt32LE(0x400, sOffset + 20);
      }
    }
  }

  return buf;
}

describe("Deterministic Windows PE Validator", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(TEST_DIR, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it("validates a healthy AMD64 Windows PE binary (> 1MB)", () => {
    const p = join(TEST_DIR, "valid.exe");
    writeFileSync(p, createSyntheticPe());
    const res = validateWindowsPe(p);
    expect(res.valid).toBe(true);
    expect(res.error).toBeUndefined();
    expect(res.machine).toContain("AMD64");
    expect(res.fileSize).toBeGreaterThan(MINIMUM_PE_SIZE_BYTES);
    expect(res.sha256).toBeString();
  });

  it("rejects non-existent file", () => {
    const res = validateWindowsPe(join(TEST_DIR, "missing.exe"));
    expect(res.valid).toBe(false);
    expect(res.error).toBe("FILE_NOT_FOUND");
  });

  it("rejects file smaller than 1 MB", () => {
    const p = join(TEST_DIR, "tiny.exe");
    writeFileSync(p, createSyntheticPe({ size: 500 * 1024 })); // 500 KB
    const res = validateWindowsPe(p);
    expect(res.valid).toBe(false);
    expect(res.error).toContain("FILE_TOO_SMALL");
  });

  it("rejects invalid DOS header (missing MZ)", () => {
    const p = join(TEST_DIR, "bad_dos.exe");
    writeFileSync(p, createSyntheticPe({ magic: 0x1234 }));
    const res = validateWindowsPe(p);
    expect(res.valid).toBe(false);
    expect(res.error).toBe("INVALID_DOS_SIGNATURE_NOT_MZ");
  });

  it("rejects invalid PE signature (missing PE\\0\\0)", () => {
    const p = join(TEST_DIR, "bad_pe_sig.exe");
    writeFileSync(p, createSyntheticPe({ peSig: [0x58, 0x58, 0x58, 0x58] }));
    const res = validateWindowsPe(p);
    expect(res.valid).toBe(false);
    expect(res.error).toBe("INVALID_PE_SIGNATURE_NOT_PE00");
  });

  it("rejects non-AMD64 architecture (e.g. i386 0x014c)", () => {
    const p = join(TEST_DIR, "i386.exe");
    writeFileSync(p, createSyntheticPe({ machine: 0x014c }));
    const res = validateWindowsPe(p);
    expect(res.valid).toBe(false);
    expect(res.error).toContain("WRONG_MACHINE_ARCHITECTURE");
  });
});
