import { describe, expect, it } from "vitest";
import { parseSignalMessage } from "./protocol";

const hello = { v: 1, type: "hello", role: "host", sessionNonce: "A".repeat(22) };

describe("hello safety-code version", () => {
  it("retains the directional frame version and rejects unknown versions", () => {
    expect(parseSignalMessage({ ...hello, frameProtocol: 2 })).toMatchObject({ frameProtocol: 2 });
    expect(() => parseSignalMessage({ ...hello, frameProtocol: 3 })).toThrow();
  });
  it("accepts version 2 and keeps it", () => {
    expect(parseSignalMessage({ ...hello, safetyCode: 2 })).toMatchObject({ safetyCode: 2 });
  });

  it("rejects an unknown safety-code version", () => {
    expect(() => parseSignalMessage({ ...hello, safetyCode: 3 })).toThrow();
  });

  it("drops a key it does not know instead of rejecting the hello, so builds that predate the field keep connecting", () => {
    const parsed = parseSignalMessage({ ...hello, safetyCode: 2, someFutureField: "x" }) as Record<string, unknown>;
    expect(parsed).not.toHaveProperty("someFutureField");
    expect(parsed).toMatchObject({ type: "hello", safetyCode: 2 });
  });

  it("parses a hello without the field, as an older build sends it", () => {
    expect(parseSignalMessage(hello)).not.toHaveProperty("safetyCode");
  });

  it("keeps the binary file-chunk flag at version 1 and rejects any other value", () => {
    expect(parseSignalMessage({ ...hello, frameProtocol: 2, binaryFileChunks: 1 })).toMatchObject({ binaryFileChunks: 1 });
    expect(() => parseSignalMessage({ ...hello, binaryFileChunks: 2 })).toThrow();
    expect(parseSignalMessage({ ...hello, frameProtocol: 2 })).not.toHaveProperty("binaryFileChunks");
  });
});
