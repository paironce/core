import { describe, expect, it } from "vitest";
import { randomBytes, toBase64Url } from "./crypto";
import {
  SAFETY_CODE_DIGITS, createDeviceProof, derivePairingSas, deviceSessionSecret, equalPairingCodes, parsePairingPayload, verifyDeviceProof,
  type DeviceProofInput, type PeerIdentityDescriptor,
} from "./pairing";

async function device(id: string) {
  const keys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const publicKey = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)));
  return { privateKey: keys.privateKey, descriptor: { id, name: "Test device", publicKey } satisfies PeerIdentityDescriptor };
}

const room = "room_for_pairing_tests_0001";

describe("pairing cryptography", () => {
  it("gives both devices the same session secret, bound to the room and the nonce", async () => {
    const [a, b, c] = await Promise.all([device("device_aaaaaaaaaaaa"), device("device_bbbbbbbbbbbb"), device("device_cccccccccccc")]);
    const nonce = randomBytes(32);
    const secret = await deviceSessionSecret(a.privateKey, a.descriptor, b.descriptor, nonce, room);
    expect(await deviceSessionSecret(b.privateKey, b.descriptor, a.descriptor, nonce, room)).toEqual(secret);
    expect(await deviceSessionSecret(a.privateKey, a.descriptor, b.descriptor, nonce, room + "x")).not.toEqual(secret);
    expect(await deviceSessionSecret(a.privateKey, a.descriptor, b.descriptor, randomBytes(32), room)).not.toEqual(secret);
    expect(await deviceSessionSecret(c.privateKey, c.descriptor, a.descriptor, nonce, room)).not.toEqual(secret);
  });

  it("shows the same 13-digit safety code on both screens, and a different one when a key was replaced", async () => {
    const [host, join, attacker] = await Promise.all([device("host_device_000001"), device("join_device_000001"), device("attacker_device_01")]);
    const nonce = randomBytes(32);
    const atHost = await derivePairingSas(host.privateKey, host.descriptor, join.descriptor, nonce, room);
    expect(atHost).toMatch(new RegExp(`^\\d{${SAFETY_CODE_DIGITS}}$`));
    expect(await derivePairingSas(join.privateKey, join.descriptor, host.descriptor, nonce, room)).toBe(atHost);
    // A relay that hands each side its own key: each side computes a code with the attacker, and the two codes differ.
    const hostSees = await derivePairingSas(host.privateKey, host.descriptor, attacker.descriptor, nonce, room);
    const joinSees = await derivePairingSas(join.privateKey, join.descriptor, attacker.descriptor, nonce, room);
    expect(hostSees).not.toBe(joinSees);
  });

  it("accepts a possession proof only for its own keys, direction and claim", async () => {
    const [host, join] = await Promise.all([device("host_device_000002"), device("join_device_000002")]);
    const base: Omit<DeviceProofInput, "privateKey" | "peerPublicKey"> = {
      invitationSecret: randomBytes(32), roomId: room, claimId: "claim_0000000000000001",
      host: host.descriptor, join: join.descriptor, code: "123456", direction: "join-claim",
    };
    const proof = await createDeviceProof({ ...base, privateKey: join.privateKey, peerPublicKey: host.descriptor.publicKey });
    expect(await verifyDeviceProof({ ...base, privateKey: host.privateKey, peerPublicKey: join.descriptor.publicKey }, proof)).toBe(true);
    expect(await verifyDeviceProof({ ...base, direction: "join-confirm", privateKey: host.privateKey, peerPublicKey: join.descriptor.publicKey }, proof)).toBe(false);
    expect(await verifyDeviceProof({ ...base, claimId: "claim_0000000000000002", privateKey: host.privateKey, peerPublicKey: join.descriptor.publicKey }, proof)).toBe(false);
    expect(await verifyDeviceProof({ ...base, code: "654321", privateKey: host.privateKey, peerPublicKey: join.descriptor.publicKey }, proof)).toBe(false);
  });

  it("parses only well-formed pairing messages and compares codes without an early exit", async () => {
    const join = await device("join_device_000003");
    const claim = { type: "pair-claim", claimId: "claim_0000000000000003", code: "123456", device: join.descriptor, proof: "A".repeat(43) };
    expect(parsePairingPayload(JSON.stringify(claim))).toEqual(claim);
    expect(() => parsePairingPayload(JSON.stringify({ ...claim, code: "12345" }))).toThrow();
    expect(() => parsePairingPayload(JSON.stringify({ ...claim, type: "pair-other" }))).toThrow();
    expect(() => parsePairingPayload(JSON.stringify({ type: "pair-result", claimId: claim.claimId, accepted: true }))).toThrow();
    expect(equalPairingCodes("123456", "123456")).toBe(true);
    expect(equalPairingCodes("123456", "123457")).toBe(false);
    expect(equalPairingCodes("123456", "12345")).toBe(false);
  });
});
