# @paironce/core

PairOnce — browser-to-browser file transfer between your devices. No app, no account, files never stored on a server.

This is the part of [PairOnce](https://paironce.com) that encrypts and moves your files, published so that the privacy
claims can be checked rather than believed. paironce.com 2.9.0 runs exactly this code.

| Module | What it does |
| --- | --- |
| `crypto` | Per-connection, per-direction AES-256-GCM frame keys (HKDF-SHA-256); chunk encryption with additional data that binds each chunk to its transfer, index, direction and frame type |
| `pairing` | Device session secret from P-256 ECDH, the 13-digit safety code, possession proofs (HMAC-SHA-256), pairing message parsing |
| `protocol` | Schemas of the signaling and DataChannel messages (zod) |
| `binary-frame` | The binary file-chunk frame |
| `chunk-assembler` | Collects decrypted chunks in order into a Blob in runs of a few MiB |
| `receive-window` | Flow control: how far the sender may run ahead of what the receiver has written |
| `constants` | Chunk size |

What it is not: a client or a server. The web app, the signaling service and the relay are not part of this repository.
The protocol they speak is described in [paironce/protocol](https://github.com/paironce/protocol), including what each service can and cannot see.

## Use

```sh
npm install
npm test
npm run typecheck
```

The package exports TypeScript source (`src/index.ts`) and needs Web Crypto (current browsers, Node 20+, Workers).
It is not on npm yet; depend on this repository by tag (`github:paironce/core#v2.9.0`).

## Versions

Releases are tagged `vX.Y.Z` and match the paironce.com version that runs them. Each production release is recorded in
[paironce/security](https://github.com/paironce/security/blob/main/RELEASES.md).

## Security

Please report vulnerabilities privately: see [SECURITY](https://github.com/paironce/security/blob/main/SECURITY.md).

## License

Apache-2.0 (see `LICENSE`). The PairOnce™ name and logo are not covered: see `TRADEMARK.md`.

Contributions are welcome: bug reports, tests and documentation. Please sign your commits off (`git commit -s`, the
Developer Certificate of Origin); no CLA is needed.
