import { z } from "zod";

export const PROTOCOL_VERSION = 1 as const;

const descriptionSchema = z.object({
  type: z.enum(["offer", "answer"]),
  sdp: z.string().min(1).max(64 * 1024),
});

const iceCandidateSchema = z.object({
  candidate: z.string().max(8 * 1024),
  sdpMid: z.string().max(256).nullable().optional(),
  sdpMLineIndex: z.number().int().nonnegative().nullable().optional(),
  usernameFragment: z.string().max(256).nullable().optional(),
});

/** 2 GB in the smallest chunks allowed (16 KiB) needs 122,071 chunks; this is the next power of two. */
export const MAX_FILE_CHUNKS = 131_072;

const helloSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  type: z.literal("hello"),
  role: z.enum(["host", "join"]),
  // Fresh per-connection nonce used to derive the application frame key.
  // It is public handshake context, not a credential.
  sessionNonce: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  // The identity fields are public device descriptors. The corresponding
  // private key never crosses the signaling channel.
  deviceId: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/).optional(),
  deviceName: z.string().min(1).max(80).optional(),
  devicePublicKey: z.string().regex(/^[A-Za-z0-9_-]{40,200}$/).optional(),
  // Capabilities are negotiated per DataChannel and bound into the frame key when both sides send a list (protocol, section 5.2).
  capabilities: z.array(z.enum(["file-approval-v1", "offer-preview-v1"])).max(8).optional(),
  // Safety-code version (pairing-sas-v2). A separate field, not a capability: a peer that predates it drops unknown keys
  // instead of rejecting the whole hello, so it keeps connecting and simply cannot pair with a safety code.
  safetyCode: z.literal(2).optional(),
  // Parsed as optional to give older peers a clear refresh message; current sessions require version 2.
  frameProtocol: z.literal(2).optional(),
  // Binary file-chunk frames (binary-frame.ts). A separate optional field so a peer that predates it drops the
  // key and keeps using JSON chunks; binary frames are used only when both hellos carry it.
  binaryFileChunks: z.literal(1).optional(),
  // This side writes large incoming files to disk and accepts offers up to 2 GB.
  // A separate optional field for the same reason: a peer that predates it drops the key and keeps offering up to 50 MiB.
  largeFiles: z.literal(1).optional(),
  // This side reports how far it has handled an incoming file and keeps a sender within its receive window
  // (receive-window.ts). Optional for the same reason: without it in both hellos neither side changes.
  receiveWindow: z.literal(1).optional(),
});

export const signalMessageSchema = z.discriminatedUnion("type", [
  helloSchema,
  z.object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("offer"),
    sessionNonce: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
    description: descriptionSchema.extend({ type: z.literal("offer") }),
  }),
  z.object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("answer"),
    sessionNonce: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
    description: descriptionSchema.extend({ type: z.literal("answer") }),
  }),
  z.object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("ice"),
    candidate: iceCandidateSchema,
  }),
]);

const idSchema = z.string().regex(/^[A-Za-z0-9_-]{16,128}$/);
const encodedBytesSchema = z.string().regex(/^[A-Za-z0-9_-]+$/).max(256 * 1024);
const encryptedControlSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  transferId: idSchema,
  noncePrefix: encodedBytesSchema,
  ciphertext: encodedBytesSchema,
  plainSize: z.number().int().positive().max(4096),
});

export const dataFrameSchema = z.discriminatedUnion("type", [
  encryptedControlSchema.extend({ type: z.literal("pair-claim") }),
  encryptedControlSchema.extend({ type: z.literal("pair-result") }),
  encryptedControlSchema.extend({ type: z.literal("pair-confirm") }),
  encryptedControlSchema.extend({ type: z.literal("file-offer") }),
  encryptedControlSchema.extend({ type: z.literal("file-decision") }),
  encryptedControlSchema.extend({ type: z.literal("file-cancel") }),
  encryptedControlSchema.extend({ type: z.literal("file-receipt") }),
  encryptedControlSchema.extend({ type: z.literal("file-progress") }),
  // A small JPEG in a JSON envelope (offer-preview-v1): larger than the other control frames, still tiny.
  encryptedControlSchema.extend({ type: z.literal("file-preview"), plainSize: z.number().int().positive().max(24 * 1024) }),
  z.object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("text"),
    transferId: idSchema,
    noncePrefix: encodedBytesSchema,
    ciphertext: encodedBytesSchema,
    plainSize: z.number().int().nonnegative().max(256 * 1024),
  }),
  z.object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("file-meta"),
    transferId: idSchema,
    name: z.string().min(1).max(512),
    mime: z.string().max(256),
    // Up to 2 GB. The session holds each file to the limit it
    // announced: 50 MiB unless it writes large files to disk; this schema only bounds what can be parsed.
    size: z.number().int().nonnegative().max(2_000_000_000),
    chunkSize: z.number().int().min(16 * 1024).max(64 * 1024),
    totalChunks: z.number().int().positive().max(MAX_FILE_CHUNKS),
    noncePrefix: encodedBytesSchema,
    // Continuing a file the receiver kept after a dropped connection: chunks before this index are already there.
    // Optional, so a peer that predates it drops the key; a sender only sets it when the receiver asked for it.
    resumeFrom: z.number().int().positive().max(MAX_FILE_CHUNKS - 1).optional(),
  }),
  z.object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("file-chunk"),
    transferId: idSchema,
    index: z.number().int().nonnegative().max(MAX_FILE_CHUNKS - 1),
    ciphertext: encodedBytesSchema,
  }),
  z.object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("file-complete"),
    transferId: idSchema,
  }),
  z.object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("file-ack"),
    transferId: idSchema,
  }),
]);

export type SignalMessage = z.infer<typeof signalMessageSchema>;
export type DataFrame = z.infer<typeof dataFrameSchema>;


export function parseSignalMessage(input: unknown): SignalMessage {
  const message = signalMessageSchema.parse(input);
  if (message.type === "hello") {
    const present = [message.deviceId, message.deviceName, message.devicePublicKey].filter((item) => item !== undefined).length;
    if (present !== 0 && present !== 3) throw new Error("Device identity fields must be supplied together");
  }
  return message;
}
export function parseDataFrame(input: unknown): DataFrame {
  return dataFrameSchema.parse(input);
}
