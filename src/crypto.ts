const encoder = new TextEncoder();

export interface ChunkContext {
  transferId: string;
  kind: "text" | "file";
  chunkIndex: number;
  totalChunks: number;
  plainSize: number;
  /** Required for live frame protocol 2; omitted only by the offline chunk format. */
  channel?: {
    sender: "host" | "join";
    frameType: "text" | "file-chunk" | "file-preview" | "file-offer" | "file-decision" | "file-cancel" | "file-receipt"
      | "file-progress" | "pair-claim" | "pair-result" | "pair-confirm" | "live";
  };
}
function webCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable in this browser");
  }
  return globalThis.crypto;
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new RangeError("Random byte length must be a positive integer");
  }
  return webCrypto().getRandomValues(new Uint8Array(length));
}

export function generateSessionSecret(): Uint8Array<ArrayBuffer> {
  return randomBytes(32);
}

export function createNoncePrefix(): Uint8Array<ArrayBuffer> {
  return randomBytes(8);
}

export async function importSessionKey(secret: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  if (secret.byteLength !== 32) {
    throw new RangeError("A session secret must be exactly 32 bytes");
  }
  return webCrypto().subtle.importKey("raw", secret, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Derive an application DataChannel key for one WebRTC session.
 *
 * The invitation secret authenticates the peers, while the two fresh nonces
 * make the resulting key unique to this connection.  The nonces are
 * public handshake values; they are only used as HKDF context and never as
 * secrets.  A frame captured from another connection therefore cannot be
 * replayed into a later connection, even when the invitation is reused.
 *
 * An optional context (both sides' capability lists, in role order) is appended to the HKDF info. Two ends that
 * disagree about it derive different keys, so a list changed in transit fails closed instead of being accepted.
 */
export async function deriveDataChannelKey(
  secret: Uint8Array<ArrayBuffer>,
  hostNonce: Uint8Array<ArrayBuffer>,
  joinNonce: Uint8Array<ArrayBuffer>,
  context?: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  if (secret.byteLength !== 32) throw new RangeError("A session secret must be exactly 32 bytes");
  if (hostNonce.byteLength !== 16 || joinNonce.byteLength !== 16) {
    throw new RangeError("DataChannel session nonces must be exactly 16 bytes");
  }
  const keyMaterial = await webCrypto().subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  const label = encoder.encode("PairOnce DataChannel key v1");
  const extra = context ?? new Uint8Array(0);
  const info = new Uint8Array(label.byteLength + hostNonce.byteLength + joinNonce.byteLength + extra.byteLength);
  info.set(label, 0);
  info.set(hostNonce, label.byteLength);
  info.set(joinNonce, label.byteLength + hostNonce.byteLength);
  info.set(extra, label.byteLength + hostNonce.byteLength + joinNonce.byteLength);
  return webCrypto().subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode("PairOnce DataChannel salt v1"),
      info,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Separate keys for each sender prevent reflection, including when both sides choose the same nonce. */
export async function deriveDirectionalDataChannelKeys(
  secret: Uint8Array<ArrayBuffer>,
  hostNonce: Uint8Array<ArrayBuffer>,
  joinNonce: Uint8Array<ArrayBuffer>,
  context?: Uint8Array<ArrayBuffer>,
): Promise<{ host: CryptoKey; join: CryptoKey }> {
  const derive = (sender: "host" | "join") => deriveDataChannelKey(secret, hostNonce, joinNonce,
    encoder.encode(JSON.stringify(["paironce-frame-v2", sender, context ? toBase64Url(context) : null])));
  const [host, join] = await Promise.all([derive("host"), derive("join")]);
  return { host, join };
}

export function createIv(
  prefix: Uint8Array<ArrayBuffer>,
  chunkIndex: number,
): Uint8Array<ArrayBuffer> {
  if (prefix.byteLength !== 8) {
    throw new RangeError("Nonce prefix must be exactly 8 bytes");
  }
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex > 0xffff_ffff) {
    throw new RangeError("Chunk index must fit an unsigned 32-bit counter");
  }
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  new DataView(iv.buffer).setUint32(8, chunkIndex, false);
  return iv;
}

function additionalData(context: ChunkContext): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(context.chunkIndex) || context.chunkIndex < 0) {
    throw new RangeError("Invalid chunk index");
  }
  if (!Number.isSafeInteger(context.totalChunks) || context.totalChunks <= 0) {
    throw new RangeError("Invalid total chunk count");
  }
  if (!Number.isSafeInteger(context.plainSize) || context.plainSize < 0) {
    throw new RangeError("Invalid plaintext size");
  }
  return encoder.encode(
    JSON.stringify([
      context.channel ? 2 : 1,
      context.transferId,
      context.kind,
      context.chunkIndex,
      context.totalChunks,
      context.plainSize,
      ...(context.channel ? [context.channel.sender, context.channel.frameType] : []),
    ]),
  );
}

export async function encryptChunk(
  key: CryptoKey,
  noncePrefix: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  context: ChunkContext,
): Promise<Uint8Array<ArrayBuffer>> {
  const ciphertext = await webCrypto().subtle.encrypt(
    {
      name: "AES-GCM",
      iv: createIv(noncePrefix, context.chunkIndex),
      additionalData: additionalData(context),
      tagLength: 128,
    },
    key,
    plaintext,
  );
  return new Uint8Array(ciphertext);
}

export async function decryptChunk(
  key: CryptoKey,
  noncePrefix: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
  context: ChunkContext,
): Promise<Uint8Array<ArrayBuffer>> {
  const plaintext = await webCrypto().subtle.decrypt(
    {
      name: "AES-GCM",
      iv: createIv(noncePrefix, context.chunkIndex),
      additionalData: additionalData(context),
      tagLength: 128,
    },
    key,
    ciphertext,
  );
  return new Uint8Array(plaintext);
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url value");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
