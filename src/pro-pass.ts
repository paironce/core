/**
 * A Pro pass (2.19.1, audit F02): the service's signature that a device, proven by its key, has PairOnce Pro until a
 * time. A Pro device sends it in its hello; the other device checks it against the service's public key (/api/config,
 * `proPassKey`) and against the device it actually paired with, so `pro: 1` alone no longer turns Pro on for a peer.
 * The signature is ECDSA P-256 with SHA-256, in the raw r‖s form Web Crypto makes.
 */
export interface ProPassClaims { v: 1; device: string; key: string; exp: number }

export const PRO_PASS_PATTERN = /^[A-Za-z0-9_-]{40,400}\.[A-Za-z0-9_-]{86}$/;
/** A pass lasts a day; the app asks for a new one with its license check. */
export const PRO_PASS_MS = 24 * 3_600_000;

function bytes(raw: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(raw)) throw new Error('invalid_pro_pass_encoding');
  return Uint8Array.from(atob(raw.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

function base64(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The service signs the claims with its private ECDSA key. */
export async function signProPass(privateKey: CryptoKey, claims: ProPassClaims): Promise<string> {
  const body = base64(new TextEncoder().encode(JSON.stringify([claims.v, claims.device, claims.key, claims.exp])));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(body)));
  return `${body}.${base64(signature)}`;
}

/** Whether `pass` is the service's, for this device and key, and not expired. */
export async function verifyProPass(serviceKey: string, pass: string, device: string, devicePublicKey: string, now = Date.now()): Promise<boolean> {
  try {
    if (!PRO_PASS_PATTERN.test(pass) || !/^[A-Za-z0-9_-]{87}$/.test(serviceKey)) return false;
    const [body, signature] = pass.split('.') as [string, string];
    const claims = JSON.parse(new TextDecoder().decode(bytes(body))) as unknown;
    if (!Array.isArray(claims) || claims.length !== 4) return false;
    const [v, claimedDevice, key, exp] = claims as [unknown, unknown, unknown, unknown];
    if (v !== 1 || claimedDevice !== device || key !== devicePublicKey || typeof exp !== 'number' || !(exp > now)) return false;
    const publicKey = await crypto.subtle.importKey('raw', bytes(serviceKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, bytes(signature), new TextEncoder().encode(body));
  } catch { return false; }
}
