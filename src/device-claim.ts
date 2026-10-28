/**
 * A device proves it holds the ECDH key it claims (2.19.0, audit F01). The service keeps one ECDH key pair; the browser
 * combines its private key with the service's public key, the service its private key with the device's, and both get
 * the same MAC. The service grants Pro relay, spends relay packs and moves a device between licenses only for a device
 * that proved its key; a device ID alone is public and proves nothing.
 */
export type DeviceClaimPurpose = 'signal' | 'activate';

export interface DeviceClaim {
  purpose: DeviceClaimPurpose;
  /** What the proof is for: the signaling session for `signal`, the license code for `activate`. */
  binding: string;
  deviceId: string;
  /** The device's ECDH public key, raw P-256 in base64url. */
  publicKey: string;
  serverPublicKey: string;
  issuedAt: number;
}

function bytes(raw: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(raw)) throw new Error('invalid_device_claim_encoding');
  return Uint8Array.from(atob(raw.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

function base64(value: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const DEVICE_CLAIM_KEY_PATTERN = /^[A-Za-z0-9_-]{87}$/;
export const DEVICE_CLAIM_PROOF_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The MAC for a claim, from this side's private key and the other side's public key (the device's or the service's). */
export async function deviceClaimProof(privateKey: CryptoKey, peerPublicKey: string, c: DeviceClaim): Promise<string> {
  if (privateKey.type !== 'private' || privateKey.algorithm.name !== 'ECDH' || !Number.isSafeInteger(c.issuedAt)
    || (c.purpose !== 'signal' && c.purpose !== 'activate') || !/^[A-Za-z0-9_-]{16,128}$/.test(c.binding)
    || !/^[A-Za-z0-9_-]{16,128}$/.test(c.deviceId) || !DEVICE_CLAIM_KEY_PATTERN.test(c.publicKey)
    || !DEVICE_CLAIM_KEY_PATTERN.test(c.serverPublicKey) || !DEVICE_CLAIM_KEY_PATTERN.test(peerPublicKey)) throw new Error('invalid_device_claim');
  const publicKey = await crypto.subtle.importKey('raw', bytes(peerPublicKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const key = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const hmac = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32),
    info: new TextEncoder().encode('paironce-device-claim-v1') }, key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return base64(await crypto.subtle.sign('HMAC', hmac,
    new TextEncoder().encode(JSON.stringify([c.purpose, c.binding, c.deviceId, c.publicKey, c.serverPublicKey, c.issuedAt]))));
}
