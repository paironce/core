import { describe, expect, it } from "vitest";
import {
  createIv,
  createNoncePrefix,
  deriveDataChannelKey,
  deriveDirectionalDataChannelKeys,
  decryptChunk,
  encryptChunk,
  generateSessionSecret,
  importSessionKey,
  randomBytes,
} from "./crypto";

const context = {
  transferId: "transfer_123456789",
  kind: "file" as const,
  chunkIndex: 0,
  totalChunks: 2,
  plainSize: 4,
};

describe("chunk encryption", () => {
  it("separates sender keys and authenticates frame type and sender", async () => {
    const secret = generateSessionSecret();
    const hostNonce = randomBytes(16), joinNonce = randomBytes(16);
    const keys = await deriveDirectionalDataChannelKeys(secret, hostNonce, joinNonce);
    const peerKeys = await deriveDirectionalDataChannelKeys(secret, hostNonce, joinNonce);
    const prefix = createNoncePrefix(), plain = new Uint8Array([1, 2, 3, 4]);
    const frameContext = { ...context, kind: "text" as const, channel: { sender: "host" as const, frameType: "pair-claim" as const } };
    const sealed = await encryptChunk(keys.host, prefix, plain, frameContext);
    await expect(decryptChunk(peerKeys.host, prefix, sealed, frameContext)).resolves.toEqual(plain);
    await expect(decryptChunk(keys.join, prefix, sealed, frameContext)).rejects.toThrow();
    await expect(decryptChunk(keys.host, prefix, sealed, { ...frameContext, channel: { sender: "join", frameType: "pair-claim" } })).rejects.toThrow();
    await expect(decryptChunk(keys.host, prefix, sealed, { ...frameContext, channel: { sender: "host", frameType: "text" } })).rejects.toThrow();
    await expect(decryptChunk(keys.host, prefix, sealed, context)).rejects.toThrow();
    const legacy = await deriveDataChannelKey(secret, hostNonce, joinNonce);
    await expect(decryptChunk(legacy, prefix, sealed, frameContext)).rejects.toThrow();
  });
  it("round-trips plaintext", async () => {
    const key = await importSessionKey(generateSessionSecret());
    const prefix = createNoncePrefix();
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    const ciphertext = await encryptChunk(key, prefix, plaintext, context);

    await expect(decryptChunk(key, prefix, ciphertext, context)).resolves.toEqual(plaintext);
    expect(ciphertext).not.toEqual(plaintext);
  });

  it("rejects tampering and changed authenticated metadata", async () => {
    const key = await importSessionKey(generateSessionSecret());
    const prefix = createNoncePrefix();
    const ciphertext = await encryptChunk(key, prefix, new Uint8Array([1, 2, 3, 4]), context);
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;

    await expect(decryptChunk(key, prefix, ciphertext, context)).rejects.toThrow();

    const valid = await encryptChunk(key, prefix, new Uint8Array([1, 2, 3, 4]), context);
    await expect(
      decryptChunk(key, prefix, valid, { ...context, transferId: "transfer_987654321" }),
    ).rejects.toThrow();
  });

  it("derives a distinct IV for every chunk counter", () => {
    const prefix = new Uint8Array(8) as Uint8Array<ArrayBuffer>;
    expect(createIv(prefix, 0)).not.toEqual(createIv(prefix, 1));
    expect(() => createIv(prefix, 0x1_0000_0000)).toThrow(RangeError);
  });

  it("binds frame encryption to both fresh DataChannel session nonces", async () => {
    const secret = generateSessionSecret();
    const hostNonce = randomBytes(16);
    const joinNonce = randomBytes(16);
    const nextHostNonce = randomBytes(16);
    const oldKey = await deriveDataChannelKey(
      secret,
      hostNonce,
      joinNonce,
    );
    const newKey = await deriveDataChannelKey(
      secret,
      nextHostNonce,
      joinNonce,
    );
    const sessionContext = { ...context, transferId: "transfer_replay_guard" };
    const prefix = createNoncePrefix();
    const ciphertext = await encryptChunk(oldKey, prefix, new Uint8Array([9, 8, 7]), {
      ...sessionContext,
      plainSize: 3,
    });

    await expect(decryptChunk(oldKey, prefix, ciphertext, { ...sessionContext, plainSize: 3 })).resolves.toEqual(
      new Uint8Array([9, 8, 7]),
    );
    await expect(decryptChunk(newKey, prefix, ciphertext, { ...sessionContext, plainSize: 3 })).rejects.toThrow();
  });

  it("binds the capability context into the key, and matching contexts agree", async () => {
    const secret = generateSessionSecret();
    const hostNonce = randomBytes(16);
    const joinNonce = randomBytes(16);
    const prefix = createNoncePrefix();
    const chunkContext = { ...context, transferId: "transfer_capability_guard", plainSize: 3 };
    const plain = new Uint8Array([4, 5, 6]);
    const bound = new TextEncoder().encode('["paironce-capabilities-v1",["file-approval-v1"],["file-approval-v1"]]');
    const stripped = new TextEncoder().encode('["paironce-capabilities-v1",[],["file-approval-v1"]]');
    const boundKey = await deriveDataChannelKey(secret, hostNonce, joinNonce, bound);
    const boundAgain = await deriveDataChannelKey(secret, hostNonce, joinNonce, bound);
    const strippedKey = await deriveDataChannelKey(secret, hostNonce, joinNonce, stripped);
    const bareKey = await deriveDataChannelKey(secret, hostNonce, joinNonce);
    const sealed = await encryptChunk(boundKey, prefix, plain, chunkContext);
    await expect(decryptChunk(boundAgain, prefix, sealed, chunkContext)).resolves.toEqual(plain);
    // A list changed in transit leaves the ends with different keys: frames fail instead of passing.
    await expect(decryptChunk(strippedKey, prefix, sealed, chunkContext)).rejects.toThrow();
    await expect(decryptChunk(bareKey, prefix, sealed, chunkContext)).rejects.toThrow();
    // Without a context the original derivation is unchanged, so a peer that sent no list still reads its frames.
    const bareSealed = await encryptChunk(bareKey, prefix, plain, chunkContext);
    await expect(decryptChunk(await deriveDataChannelKey(secret, hostNonce, joinNonce), prefix, bareSealed, chunkContext)).resolves.toEqual(plain);
  });
});
