# Design notes

These are the decisions behind `hybrid-pq-sig`, written down so the next person does not have to guess why things look the way they do.

## Threat model

What we want to hold:

1. **Unforgeability if either scheme holds.** Someone who can break Ed25519 (a quantum adversary) or ML-DSA-65 (a cryptanalytic or implementation break), but not both, still cannot forge.
2. **No stripping.** A valid hybrid signature must not give you a valid standalone Ed25519 or ML-DSA signature on anything useful.
3. **No cross-domain replay.** A signature made for one chain or one application must not verify for another.
4. **Key binding.** A signature is tied to one composite key, not to any key that happens to share a half.

What we do not try to solve here: side channels on the signing device, key storage, and consensus level questions like validator key rotation. Those need their own work.

## Why sign a bound message instead of the raw message

The obvious construction is "sign `msg` with both keys and concatenate." It fails goal 2. The Ed25519 half is a perfectly valid Ed25519 signature over `msg` and can be presented to any system that trusts the same classical key.

Signing `domain || suite || H(pk) || ctx || msg` fixes that. The Ed25519 half only verifies over a message nobody else would ever ask to sign, and it names the composite key it belongs to.

Lengths are encoded explicitly so there is no ambiguity between where `ctx` ends and `msg` begins.

## Why one seed

Two independent seeds are marginally cleaner in theory. In practice they mean two backups, and a user who loses one of them loses the account after enforcement. HKDF with distinct labels gives independent keys from one seed, and the wallet UX stays the same as today.

## Why deterministic ML-DSA

FIPS 204 allows hedged (randomized) or deterministic signing. Deterministic is easier to test, gives stable vectors, and does not depend on the RNG of whatever device is signing. Hedged signing helps against some fault and side channel attacks. For a validator HSM I would switch to hedged. The flag is one line in `Sign`.

## Why ML-DSA-65

ML-DSA-44 is smaller (1,312 B key, 2,420 B signature) and targets NIST level 2. ML-DSA-65 targets level 3. For long lived account keys on a public ledger I would rather have the margin. If size is the dominant constraint, the suite byte exists so a chain can register a 44 based suite later without breaking anything.

FN-DSA (Falcon) gives much smaller signatures, but it needs careful floating point handling during signing and is harder to implement safely on constrained hardware. SLH-DSA (SPHINCS+) is the conservative hash based choice, with signatures in the 8 to 50 KB range, which is too big for per transaction use on most chains but a reasonable fit for rare, high value operations like validator set changes or bridge governance.

## Where the size hurts on a real chain

Taking a Cosmos SDK style chain as the reference:

- **Transactions.** Signature goes from 64 B to 3,374 B. For a simple transfer that is most of the transaction. Block gas and byte limits need to be revisited or throughput drops.
- **Account state.** If the full public key lives in account state, that is ~2 KB per account. Registering the key once and storing only a hash, then having transactions carry the key only on first use, keeps state small.
- **Gossip.** Mempool bandwidth rises roughly in line with transaction size. Compact block relay helps.
- **Light clients.** Validator signature sets in commits grow a lot. With 100 validators a commit carries ~330 KB of PQ signatures. This is the strongest argument for keeping validator consensus keys on a separate track from user account keys, and for looking at aggregation friendly schemes for consensus specifically.
- **Archive nodes.** Signatures on old, finalized blocks can be pruned by nodes that trust the chain's finality, which cuts long term storage for everyone except full archive nodes.

## Migration shape

The height based `Policy` exists because a hard switch does not work on an open network. The rough plan:

1. Ship verification support in a release, disabled.
2. Open the window at `UpgradeOpen`. Accounts submit a rotation transaction signed by their legacy key that registers a composite key.
3. Wallets, exchanges and custodians update during the window. Track the share of active accounts that have rotated.
4. Set `Enforce` by governance only once that share is high enough, not on a date picked a year in advance.
5. After `Enforce`, legacy keys can still sign one thing: a rotation, for a limited recovery period, if governance decides it wants that escape hatch. That decision is policy, not code, and it is deliberately left out of this library.

## Open questions

- Following the final IETF composite ML-DSA encoding once it settles.
- Whether validator consensus should use the same composite or something aggregation friendly.
- Hardware wallet support. Most current secure elements do not have the RAM for ML-DSA-65 signing, which may force hybrid keys to live on the host for a while.
