# hybrid-pq-sig

Composite Ed25519 + ML-DSA-65 signatures for ledgers that need to start their post-quantum migration now, without trusting a brand new scheme on its own.

A signature is valid only when both halves verify. Ed25519 covers you if an ML-DSA implementation turns out to be broken. ML-DSA covers you once a cryptographically relevant quantum computer exists. You pay for that in bytes, and the numbers are below so nobody is surprised later.

## Why hybrid and why now

Anything signed today with a classical key and stored on a public chain stays there forever. The "harvest now, forge later" argument is weaker for signatures than it is for key exchange, but account keys on a chain live for years and the rotation itself takes years. NIST finalized ML-DSA as FIPS 204 in August 2024, and national guidance (CNSA 2.0 in the US, similar timelines in the EU) is pushing for PQ signatures across the 2030s. Chains that start the migration late will end up doing it in a hurry.

Going PQ-only right away is the other mistake. Lattice schemes are well studied on paper, but the production track record of the implementations is short. A composite gives you a safe window to find out.

## What is in here

| Path | What it does |
|---|---|
| `hybrid/hybrid.go` | Key derivation, signing, verification, encoding, addresses |
| `hybrid/migration.go` | Height-based policy for moving a chain from legacy to hybrid keys |
| `hybrid/hybrid_test.go` | Tests for tampering, key binding, cross-chain replay, stripping, policy windows; benchmarks |
| `cmd/hpqsig` | Small CLI for keygen, sign, verify and size comparison |
| `docs/DESIGN.md` | Construction, threat model, and the trade-offs I made on purpose |

## Construction in short

- One 32 byte master seed. HKDF-SHA512 derives the Ed25519 seed and the ML-DSA-65 seed with separate labels, so a wallet still has one backup.
- Both halves sign the same bound message:
  `"HPQSIG-v1" || suite || SHA3-256(composite pk) || len(ctx) || ctx || len(msg) || msg`
- `ctx` is meant for the chain ID. A signature for mainnet is useless on a testnet.
- Committing to the full composite public key means the Ed25519 half cannot be lifted out and replayed as a plain Ed25519 signature. There is a test for exactly that.
- Verification always evaluates both halves before returning.
- Addresses are the first 20 bytes of SHA3-256 over the full composite key.

## Sizes and cost

| Scheme | Public key | Signature |
|---|---:|---:|
| Ed25519 | 32 B | 64 B |
| Ed25519 + ML-DSA-65 | 1,985 B | 3,374 B |

Rough numbers from `go test -bench . ./hybrid` on a 2 vCPU cloud VM:

| Operation | Time |
|---|---:|
| Hybrid sign | ~220 µs |
| Hybrid verify | ~88 µs |
| Ed25519 verify alone | ~41 µs |

Verification cost is fine. The real problem is size. A 3.3 KB signature on every transaction changes block size budgets, mempool limits, gossip bandwidth and state growth if you store keys in accounts. `docs/DESIGN.md` has notes on where that bites and a few ways to soften it (key registration once per account, signature aggregation at the block level where the scheme allows it, pruning signatures from old blocks).

## Migration policy

`Policy{UpgradeOpen, Enforce}` splits the chain's life into three periods:

1. Before `UpgradeOpen`: legacy Ed25519 only.
2. Between `UpgradeOpen` and `Enforce`: both accepted, accounts rotate.
3. From `Enforce`: hybrid only.

The window in the middle has to be long. Exchanges and custodians move slowly, and every one of them that misses the deadline turns into a pile of stuck users.

## Try it

```bash
go test ./...
go test -bench . ./hybrid
go run ./cmd/hpqsig sizes
go run ./cmd/hpqsig keygen
```

## Status

Research code. The primitives come from [cloudflare/circl](https://github.com/cloudflare/circl) and the Go standard library, and the composition is small on purpose so it is easy to review, but it has not been audited. Do not put it in front of real funds without that.

The IETF LAMPS work on composite ML-DSA is still moving. If it settles on a different encoding or binding, this repo will follow it rather than keep its own format.

## License

Apache-2.0
