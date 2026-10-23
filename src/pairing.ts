/**
 * Pairing cryptography and message parsing, without session state: the device session secret, the 13-digit safety code,
 * possession proofs and the pairing message format.
 */
import { fromBase64Url, toBase64Url } from "./crypto";

export interface PeerIdentityDescriptor {
  id: string;
  name: string;
  publicKey: string;
}

export async function deviceSessionSecret(privateKey: CryptoKey, local: PeerIdentityDescriptor,
  peer: PeerIdentityDescriptor, nonce: Uint8Array<ArrayBuffer>, room: string): Promise<Uint8Array<ArrayBuffer>> {
  const publicKey = await crypto.subtle.importKey('raw', fromBase64Url(peer.publicKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const material = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveBits']);
  const devices = [local, peer].sort((a, b) => a.id < b.id ? -1 : 1).map(d => [d.id, d.publicKey]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: nonce,
    info: new TextEncoder().encode(JSON.stringify(['paironce-device-session-v2', room, devices])) }, material, 256));
}

/**
 * Derive the safety code used for v2 device pairing: 13 decimal digits, about 43 bits (SAFETY_CODE_DIGITS). The code is
 * a display-level confirmation; the encrypted channel and ECDH possession proofs remain the authorization boundary.
 * Including both public keys, room, and the invitation nonce prevents a copied code from another pairing being
 * accepted in this room.
 */
export const SAFETY_CODE_DIGITS = 13;
export async function derivePairingSas(
  privateKey: CryptoKey,
  local: PeerIdentityDescriptor,
  peer: PeerIdentityDescriptor,
  invitationSecret: Uint8Array<ArrayBuffer>,
  roomId: string,
): Promise<string> {
  if (invitationSecret.byteLength !== 32 || !/^[A-Za-z0-9_-]{20,128}$/.test(roomId) ||
    !isDeviceDescriptor(local) || !isDeviceDescriptor(peer)) throw new Error("Invalid pairing SAS context");
  // The ECDH secret of this key pair is the input an active relay cannot choose: a substituted peer key gives the two
  // ends different secrets. Device IDs are deliberately left out. They are free text the other side picks, and putting
  // them in the transcript let an attacker search for a matching code with cheap hashing only (review R-08).
  const peerKey = await crypto.subtle.importKey("raw", fromBase64Url(peer.publicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peerKey }, privateKey, 256));
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const keys = [local.publicKey, peer.publicKey].sort();
  const info = new TextEncoder().encode(JSON.stringify(["paironce-pairing-sas-v2", roomId, ...keys]));
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: invitationSecret, info }, material, 64);
  // A 64-bit value reduced modulo 10^13: the bias is below 1e-6.
  const value = new DataView(bits).getBigUint64(0, false) % 10_000_000_000_000n;
  return String(value).padStart(SAFETY_CODE_DIGITS, "0");
}

export type PairingPayload =
  | { type: "pair-claim"; claimId: string; code: string; device: PeerIdentityDescriptor; proof: string }
  | { type: "pair-result"; claimId: string; accepted: boolean; device?: PeerIdentityDescriptor; proof?: string; reason?: string; terminal?: boolean }
  | { type: "pair-confirm"; claimId: string; proof: string };

export interface DeviceProofInput {
  privateKey: CryptoKey;
  peerPublicKey: string;
  invitationSecret: Uint8Array<ArrayBuffer>;
  roomId: string;
  claimId: string;
  host: PeerIdentityDescriptor;
  join: PeerIdentityDescriptor;
  code: string;
  direction: "join-claim" | "host-approve" | "join-confirm";
}

async function deviceProofKey(input: DeviceProofInput): Promise<CryptoKey> {
  if (input.privateKey.type !== "private" || input.privateKey.algorithm.name !== "ECDH") {
    throw new Error("A device ECDH private key is required");
  }
  const publicBytes = fromBase64Url(input.peerPublicKey);
  if (publicBytes.byteLength !== 65 || publicBytes[0] !== 4) throw new Error("Invalid device public key");
  const publicKey = await crypto.subtle.importKey(
    "raw", publicBytes, { name: "ECDH", namedCurve: "P-256" }, false, [],
  );
  const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, input.privateKey, 256);
  const keyMaterial = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: input.invitationSecret,
      info: new TextEncoder().encode("PairOnce device possession proof v1"),
    },
    keyMaterial,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"],
  );
}

function deviceProofTranscript(input: DeviceProofInput): Uint8Array<ArrayBuffer> {
  if (!/^(?:\d{6}|\d{13})$/.test(input.code)) throw new Error("Invalid pairing code for device proof");
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(input.claimId)) throw new Error("Invalid claim ID for device proof");
  return new TextEncoder().encode(JSON.stringify([
    "paironce-device-proof-v1",
    input.direction,
    input.roomId,
    input.claimId,
    input.host.id,
    input.host.publicKey,
    input.join.id,
    input.join.publicKey,
    input.code,
  ]));
}

export async function createDeviceProof(input: DeviceProofInput): Promise<string> {
  const key = await deviceProofKey(input);
  return toBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, deviceProofTranscript(input))));
}

export async function verifyDeviceProof(input: DeviceProofInput, proof: string): Promise<boolean> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(proof)) return false;
  const key = await deviceProofKey(input);
  return crypto.subtle.verify("HMAC", key, fromBase64Url(proof), deviceProofTranscript(input));
}

export function isDeviceDescriptor(value: unknown): value is PeerIdentityDescriptor {
  if (!value || typeof value !== "object") return false;
  const descriptor = value as Record<string, unknown>;
  return typeof descriptor.id === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(descriptor.id) &&
    typeof descriptor.name === "string" && descriptor.name.length > 0 && descriptor.name.length <= 80 &&
    typeof descriptor.publicKey === "string" && /^[A-Za-z0-9_-]{40,200}$/.test(descriptor.publicKey);
}

export function parsePairingPayload(raw: string): PairingPayload {
  const value: unknown = JSON.parse(raw);
  if (!value || typeof value !== "object") throw new Error("Invalid pairing message");
  const payload = value as Record<string, unknown>;
  const claimId = payload.claimId;
  if (typeof claimId !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(claimId)) {
    throw new Error("Invalid pairing claim ID");
  }
  if (payload.type === "pair-claim") {
    if (typeof payload.code !== "string" || !/^(?:\d{6}|\d{13})$/.test(payload.code) || !isDeviceDescriptor(payload.device) || !isDeviceProof(payload.proof)) {
      throw new Error("Invalid pairing claim");
    }
    return { type: "pair-claim", claimId, code: payload.code, device: payload.device, proof: payload.proof };
  }
  if (payload.type === "pair-result") {
    if (typeof payload.accepted !== "boolean") throw new Error("Invalid pairing result");
    if (payload.terminal !== undefined && typeof payload.terminal !== "boolean") throw new Error("Invalid pairing result");
    if (payload.accepted && (!isDeviceDescriptor(payload.device) || !isDeviceProof(payload.proof))) {
      throw new Error("Pairing result omitted host device or proof");
    }
    if (payload.accepted && payload.terminal) throw new Error("Accepted pairing cannot be terminal");
    if (payload.reason !== undefined && (typeof payload.reason !== "string" || payload.reason.length > 120)) {
      throw new Error("Invalid pairing rejection reason");
    }
    return {
      type: "pair-result",
      claimId,
      accepted: payload.accepted,
      ...(isDeviceDescriptor(payload.device) ? { device: payload.device } : {}),
      ...(isDeviceProof(payload.proof) ? { proof: payload.proof } : {}),
      ...(typeof payload.reason === "string" ? { reason: payload.reason } : {}),
      ...(typeof payload.terminal === "boolean" ? { terminal: payload.terminal } : {}),
    };
  }
  if (payload.type === "pair-confirm" && isDeviceProof(payload.proof)) {
    return { type: "pair-confirm", claimId, proof: payload.proof };
  }
  throw new Error("Unknown pairing message type");
}

function isDeviceProof(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

/** Compare every position without a first-mismatch early exit. Accepts a six-digit connection code or a safety code. */
export function equalPairingCodes(expected: string, actual: string): boolean {
  if (!/^(?:\d{6}|\d{13})$/.test(expected) || actual.length !== expected.length || !/^\d+$/.test(actual)) return false;
  let mismatch = 0;
  for (let index = 0; index < expected.length; index += 1) mismatch |= expected.charCodeAt(index) ^ actual.charCodeAt(index);
  return mismatch === 0;
}
