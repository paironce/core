import { describe, expect, it } from "vitest";
import { MAX_CIPHERTEXT, decodeBinaryFrame, encodeFileChunk } from "./binary-frame";

const id = "transfer_ABCDEFGHIJ-123";
const ciphertext = (n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 7) & 255);

describe("binary file-chunk frames", () => {
  it("round-trips transfer ID, index and ciphertext, with a much smaller frame than base64 JSON", () => {
    const sealed = ciphertext(32 * 1024 + 16);
    const frame = encodeFileChunk(id, 2047, sealed);
    const decoded = decodeBinaryFrame(frame);
    expect(decoded).toMatchObject({ type: "file-chunk", transferId: id, index: 2047 });
    expect([...decoded.ciphertext]).toEqual([...sealed]);
    const json = JSON.stringify({ v: 1, type: "file-chunk", transferId: id, index: 2047, ciphertext: Buffer.from(sealed).toString("base64url") });
    expect(frame.byteLength).toBeLessThan(json.length * 0.8);
  });

  it("refuses to encode anything outside the limits", () => {
    expect(() => encodeFileChunk("short", 0, ciphertext(17))).toThrow();
    expect(() => encodeFileChunk(id, 131_072, ciphertext(17))).toThrow();
    expect(() => encodeFileChunk(id, 131_071, ciphertext(17))).not.toThrow();
    expect(() => encodeFileChunk(id, -1, ciphertext(17))).toThrow();
    expect(() => encodeFileChunk(id, 0, ciphertext(16))).toThrow();
    expect(() => encodeFileChunk(id, 0, ciphertext(MAX_CIPHERTEXT + 1))).toThrow();
  });

  it("rejects frames with a wrong marker, version, type, header or size", () => {
    const good = new Uint8Array(encodeFileChunk(id, 3, ciphertext(64)));
    const tamper = (at: number, value: number) => { const copy = good.slice(); copy[at] = value; return copy.buffer; };
    expect(() => decodeBinaryFrame(tamper(0, 0x51))).toThrow("Unknown binary frame format");
    expect(() => decodeBinaryFrame(tamper(1, 2))).toThrow("Unknown binary frame format");
    expect(() => decodeBinaryFrame(tamper(2, 9))).toThrow("Unknown binary frame type");
    expect(() => decodeBinaryFrame(tamper(3, 200))).toThrow("Invalid binary frame header");
    expect(() => decodeBinaryFrame(tamper(5, 0x20))).toThrow("Invalid binary frame header"); // a space inside the ID
    const index = good.slice(); new DataView(index.buffer).setUint32(4 + id.length, 131_072, false);
    expect(() => decodeBinaryFrame(index.buffer)).toThrow("out of range");
    expect(() => decodeBinaryFrame(new ArrayBuffer(10))).toThrow("size is out of range");
    expect(() => decodeBinaryFrame(new ArrayBuffer(300_000))).toThrow("size is out of range");
  });
});
