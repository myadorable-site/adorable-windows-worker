import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";

export interface PeValidationResult {
  valid: boolean;
  error?: string;
  sha256?: string;
  fileSize?: number;
  machine?: string;
  numberOfSections?: number;
  optHeaderMagic?: string;
  peOffset?: number;
}

export const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
export const MINIMUM_PE_SIZE_BYTES = 1024 * 1024; // 1 MB

/**
 * Deterministically validates a Windows PE executable file.
 *
 * Verifies:
 * 1. file exists
 * 2. file size > 1 MB
 * 3. DOS header: bytes[0..1] == 0x4D 0x5A ("MZ")
 * 4. e_lfanew offset is within file bounds and >= 0x40
 * 5. PE signature at e_lfanew: "PE\0\0"
 * 6. COFF machine: 0x8664 = IMAGE_FILE_MACHINE_AMD64
 * 7. Section table is structurally readable
 * 8. Important header offsets are within file bounds
 */
export function validateWindowsPe(filePath: string): PeValidationResult {
  if (!existsSync(filePath)) {
    return { valid: false, error: "FILE_NOT_FOUND" };
  }

  let st;
  try {
    st = statSync(filePath);
  } catch (err) {
    return { valid: false, error: `STAT_FAILED: ${(err as Error)?.message ?? err}` };
  }

  const fileSize = st.size;
  if (fileSize <= MINIMUM_PE_SIZE_BYTES) {
    return {
      valid: false,
      fileSize,
      error: `FILE_TOO_SMALL: size is ${fileSize} bytes, minimum required is ${MINIMUM_PE_SIZE_BYTES} bytes (> 1MB)`,
    };
  }

  let buffer: Buffer;
  try {
    buffer = readFileSync(filePath);
  } catch (err) {
    return { valid: false, fileSize, error: `READ_FAILED: ${(err as Error)?.message ?? err}` };
  }

  const sha256 = createHash("sha256").update(buffer).digest("hex");

  // Check 3: DOS Header MZ signature
  if (buffer.length < 64) {
    return { valid: false, sha256, fileSize, error: "TRUNCATED_DOS_HEADER" };
  }
  if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    return { valid: false, sha256, fileSize, error: "INVALID_DOS_SIGNATURE_NOT_MZ" };
  }

  // Check 4: e_lfanew offset at 0x3C
  const e_lfanew = buffer.readUInt32LE(0x3c);
  if (e_lfanew < 0x40 || e_lfanew + 24 > buffer.length) {
    return {
      valid: false,
      sha256,
      fileSize,
      peOffset: e_lfanew,
      error: `OUT_OF_BOUNDS_E_LFANEW: ${e_lfanew}`,
    };
  }

  // Check 5: PE signature "PE\0\0"
  if (
    buffer[e_lfanew] !== 0x50 ||
    buffer[e_lfanew + 1] !== 0x45 ||
    buffer[e_lfanew + 2] !== 0x00 ||
    buffer[e_lfanew + 3] !== 0x00
  ) {
    return {
      valid: false,
      sha256,
      fileSize,
      peOffset: e_lfanew,
      error: "INVALID_PE_SIGNATURE_NOT_PE00",
    };
  }

  // Check 6: COFF File Header (20 bytes at e_lfanew + 4)
  const coffOffset = e_lfanew + 4;
  const machine = buffer.readUInt16LE(coffOffset);
  const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
  const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);

  if (machine !== IMAGE_FILE_MACHINE_AMD64) {
    return {
      valid: false,
      sha256,
      fileSize,
      machine: `0x${machine.toString(16)}`,
      error: `WRONG_MACHINE_ARCHITECTURE: expected AMD64 (0x8664), got 0x${machine.toString(16)}`,
    };
  }

  // Check 7 & 8: Optional Header & Section Table
  const optHeaderOffset = coffOffset + 20;
  if (optHeaderOffset + sizeOfOptionalHeader > buffer.length) {
    return {
      valid: false,
      sha256,
      fileSize,
      machine: "IMAGE_FILE_MACHINE_AMD64",
      error: "OUT_OF_BOUNDS_OPTIONAL_HEADER",
    };
  }

  let optHeaderMagic = "";
  if (sizeOfOptionalHeader >= 2) {
    const magic = buffer.readUInt16LE(optHeaderOffset);
    if (magic === 0x020b) optHeaderMagic = "PE32+ (64-bit)";
    else if (magic === 0x010b) optHeaderMagic = "PE32 (32-bit)";
    else optHeaderMagic = `0x${magic.toString(16)}`;
  }

  const sectionTableOffset = optHeaderOffset + sizeOfOptionalHeader;
  const SECTION_HEADER_SIZE = 40;
  if (sectionTableOffset + numberOfSections * SECTION_HEADER_SIZE > buffer.length) {
    return {
      valid: false,
      sha256,
      fileSize,
      machine: "IMAGE_FILE_MACHINE_AMD64",
      numberOfSections,
      optHeaderMagic,
      error: "OUT_OF_BOUNDS_SECTION_TABLE",
    };
  }

  // Verify section headers structurally
  for (let i = 0; i < numberOfSections; i++) {
    const sOffset = sectionTableOffset + i * SECTION_HEADER_SIZE;
    const rawDataOffset = buffer.readUInt32LE(sOffset + 20);
    const rawDataSize = buffer.readUInt32LE(sOffset + 16);
    if (rawDataSize > 0 && rawDataOffset + rawDataSize > buffer.length + 512) {
      // Small alignment tolerance allowed in some packaged PE headers, but out-of-file is corrupt
      return {
        valid: false,
        sha256,
        fileSize,
        machine: "IMAGE_FILE_MACHINE_AMD64",
        numberOfSections,
        error: `SECTION_${i}_RAW_DATA_OUT_OF_BOUNDS`,
      };
    }
  }

  return {
    valid: true,
    sha256,
    fileSize,
    machine: "IMAGE_FILE_MACHINE_AMD64 (0x8664)",
    numberOfSections,
    optHeaderMagic,
    peOffset: e_lfanew,
  };
}
