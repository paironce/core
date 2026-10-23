/**
 * Binary DataChannel frames for encrypted file chunks, used only when both devices announce `binaryFileChunks: 1` in their
 * hello. A JSON file-chunk carried the ciphertext as base64url text inside JSON: a third larger on the wire, and decoded
 * through strings and copies on arrival. This frame carries the same ciphertext as raw bytes. Encryption is unchanged:
 * the AES-GCM additional data still binds sender, frame type, transfer ID, chunk index and sizes, so a header that is
 * altered in transit makes the chunk fail to decrypt.
 *
 * Layout (big-endian):
 *   0      1 byte   0x50 ("P")
 *   1      1 byte   format version, 1
 *   2      1 byte   frame type, 1 = file-chunk
 *   3      1 byte   transfer ID length n, 16..128
 *   4      n bytes  transfer ID, ASCII [A-Za-z0-9_-]
 *   4+n    4 bytes  chunk index, 0..MAX_FILE_CHUNKS - 1
 *   8+n    rest     ciphertext (chunk plaintext + 16-byte tag), 17..MAX_CIPHERTEXT bytes
 */
import { MAX_FILE_CHUNKS } from "./protocol";

const MAGIC = 0x50;
const VERSION = 1;
const FILE_CHUNK = 1;
const ID = /^[A-Za-z0-9_-]{16,128}$/;
const MAX_INDEX = MAX_FILE_CHUNKS - 1;
/** One 32 KiB chunk plus the tag, with room for a larger chunk size the protocol schema allows (64 KiB). */
export const MAX_CIPHERTEXT = 64 * 1024 + 16;
export const MAX_BINARY_FRAME_BYTES = 8 + 128 + MAX_CIPHERTEXT;

export interface BinaryFileChunk {
  type: "file-chunk";
  transferId: string;
  index: number;
  ciphertext: Uint8Array<ArrayBuffer>;
}

export function encodeFileChunk(transferId: string, index: number, ciphertext: Uint8Array): ArrayBuffer {
  if (!ID.test(transferId)) throw new Error("Invalid transfer ID for a binary frame");
  if (!Number.isSafeInteger(index) || index < 0 || index > MAX_INDEX) throw new Error("Invalid chunk index for a binary frame");
  if (ciphertext.byteLength < 17 || ciphertext.byteLength > MAX_CIPHERTEXT) throw new Error("Invalid ciphertext size for a binary frame");
  const id = new TextEncoder().encode(transferId);
  const frame = new Uint8Array(8 + id.byteLength + ciphertext.byteLength);
  frame[0] = MAGIC; frame[1] = VERSION; frame[2] = FILE_CHUNK; frame[3] = id.byteLength;
  frame.set(id, 4);
  new DataView(frame.buffer).setUint32(4 + id.byteLength, index, false);
  frame.set(ciphertext, 8 + id.byteLength);
  return frame.buffer;
}

export function decodeBinaryFrame(data: ArrayBuffer): BinaryFileChunk {
  if (!(data instanceof ArrayBuffer) || data.byteLength < 8 + 16 + 17 || data.byteLength > MAX_BINARY_FRAME_BYTES) {
    throw new Error("Binary frame size is out of range");
  }
  const bytes = new Uint8Array(data);
  if (bytes[0] !== MAGIC || bytes[1] !== VERSION) throw new Error("Unknown binary frame format");
  if (bytes[2] !== FILE_CHUNK) throw new Error("Unknown binary frame type");
  const idLength = bytes[3]!;
  if (idLength < 16 || idLength > 128 || 8 + idLength + 17 > bytes.byteLength) throw new Error("Invalid binary frame header");
  let transferId = "";
  for (let i = 4; i < 4 + idLength; i++) transferId += String.fromCharCode(bytes[i]!);
  if (!ID.test(transferId)) throw new Error("Invalid binary frame header");
  const index = new DataView(data).getUint32(4 + idLength, false);
  if (index > MAX_INDEX) throw new Error("File chunk index is out of range");
  // A view, not a copy: the ciphertext is decrypted once and then dropped.
  return { type: "file-chunk", transferId, index, ciphertext: new Uint8Array(data, 8 + idLength) };
}
