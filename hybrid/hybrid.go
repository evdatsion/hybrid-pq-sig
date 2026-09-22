// Package hybrid implements a composite signature that pairs Ed25519 with
// ML-DSA-65 (FIPS 204). A signature is valid only when both halves verify.
//
// The point is to let a ledger start carrying post-quantum signatures today
// without betting everything on a scheme that is still young in production.
// If ML-DSA turns out to have an implementation bug, Ed25519 still holds.
// If a large quantum computer shows up, ML-DSA still holds.
//
// Both halves sign the same bound message (see boundMessage), which commits to
// the suite, the full composite public key and a caller context. That stops a
// stripping attack where someone lifts the Ed25519 half out and presents it as
// a plain Ed25519 signature somewhere else.
package hybrid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Suite identifies the algorithm pair. It is the first byte of every encoded
// key and signature so verifiers can reject mismatches before doing any math.
type Suite byte

const (
	SuiteEd25519MLDSA65 Suite = 0x01
)

const (
	domain = "HPQSIG-v1"

	SeedSize      = 32
	PublicKeySize = 1 + ed25519.PublicKeySize + mldsa65.PublicKeySize
	SignatureSize = 1 + ed25519.SignatureSize + mldsa65.SignatureSize
	AddressSize   = 20
	maxContextLen = 255
)

var (
	ErrSuite     = errors.New("hybrid: unknown or mismatched suite")
	ErrEncoding  = errors.New("hybrid: malformed encoding")
	ErrContext   = errors.New("hybrid: context longer than 255 bytes")
	ErrSignature = errors.New("hybrid: signature invalid")
	ErrShortSeed = errors.New("hybrid: seed must be 32 bytes")
)

type PublicKey struct {
	classical ed25519.PublicKey
	pq        *mldsa65.PublicKey
	encoded   []byte
}

type PrivateKey struct {
	classical ed25519.PrivateKey
	pq        *mldsa65.PrivateKey
	pub       *PublicKey
}

// GenerateKey draws a fresh 32 byte master seed from r and derives both keys.
func GenerateKey(r io.Reader) (*PublicKey, *PrivateKey, error) {
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, err
	}
	return NewKeyFromSeed(seed)
}

// NewKeyFromSeed derives both component keys from one master seed with
// HKDF-SHA512 and separate labels. One seed means one backup phrase for users,
// which matters a lot more in wallets than the elegance of the construction.
func NewKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, nil, ErrShortSeed
	}
	edSeed, err := hkdf.Key(sha512.New, seed, []byte(domain), "ed25519", ed25519.SeedSize)
	if err != nil {
		return nil, nil, err
	}
	pqSeedSlice, err := hkdf.Key(sha512.New, seed, []byte(domain), "ml-dsa-65", mldsa65.SeedSize)
	if err != nil {
		return nil, nil, err
	}
	var pqSeed [mldsa65.SeedSize]byte
	copy(pqSeed[:], pqSeedSlice)

	edPriv := ed25519.NewKeyFromSeed(edSeed)
	pqPub, pqPriv := mldsa65.NewKeyFromSeed(&pqSeed)

	pub := &PublicKey{classical: edPriv.Public().(ed25519.PublicKey), pq: pqPub}
	pub.encoded = pub.encode()
	return pub, &PrivateKey{classical: edPriv, pq: pqPriv, pub: pub}, nil
}

func (k *PrivateKey) Public() *PublicKey { return k.pub }

func (k *PublicKey) encode() []byte {
	out := make([]byte, 0, PublicKeySize)
	out = append(out, byte(SuiteEd25519MLDSA65))
	out = append(out, k.classical...)
	out = append(out, k.pq.Bytes()...)
	return out
}

// Bytes returns suite || ed25519 pk || ml-dsa-65 pk.
func (k *PublicKey) Bytes() []byte { return bytes.Clone(k.encoded) }

// Classical exposes the Ed25519 half, used by the migration policy to match a
// legacy account key against its upgraded composite key.
func (k *PublicKey) Classical() ed25519.PublicKey { return k.classical }

// Address is the first 20 bytes of SHA3-256 over the full encoded key, so an
// address commits to both halves.
func (k *PublicKey) Address() [AddressSize]byte {
	h := sha3.Sum256(k.encoded)
	var a [AddressSize]byte
	copy(a[:], h[:AddressSize])
	return a
}

func ParsePublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, ErrEncoding
	}
	if Suite(b[0]) != SuiteEd25519MLDSA65 {
		return nil, ErrSuite
	}
	edEnd := 1 + ed25519.PublicKeySize
	pq := new(mldsa65.PublicKey)
	if err := pq.UnmarshalBinary(b[edEnd:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	pk := &PublicKey{classical: bytes.Clone(b[1:edEnd]), pq: pq}
	pk.encoded = pk.encode()
	if !bytes.Equal(pk.encoded, b) {
		return nil, ErrEncoding
	}
	return pk, nil
}

// boundMessage = domain || suite || SHA3-256(pk) || len(ctx) || ctx || len(msg) || msg
func boundMessage(pk *PublicKey, ctx, msg []byte) []byte {
	pkHash := sha3.Sum256(pk.encoded)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(msg)))

	var b bytes.Buffer
	b.Grow(len(domain) + 1 + 32 + 1 + len(ctx) + 8 + len(msg))
	b.WriteString(domain)
	b.WriteByte(byte(SuiteEd25519MLDSA65))
	b.Write(pkHash[:])
	b.WriteByte(byte(len(ctx)))
	b.Write(ctx)
	b.Write(n[:])
	b.Write(msg)
	return b.Bytes()
}

// Sign produces suite || ed25519 sig || ml-dsa-65 sig. ctx is a short
// application label such as a chain ID; it keeps a signature for one network
// from being valid on another.
func (k *PrivateKey) Sign(ctx, msg []byte) ([]byte, error) {
	if len(ctx) > maxContextLen {
		return nil, ErrContext
	}
	m := boundMessage(k.pub, ctx, msg)

	sig := make([]byte, SignatureSize)
	sig[0] = byte(SuiteEd25519MLDSA65)
	copy(sig[1:], ed25519.Sign(k.classical, m))
	// Deterministic ML-DSA (randomized=false) keeps signing reproducible for
	// test vectors and for HSMs without a good RNG. Flip it if side channels
	// on the signer are a bigger worry than reproducibility.
	if err := mldsa65.SignTo(k.pq, m, []byte(domain), false, sig[1+ed25519.SignatureSize:]); err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify returns nil only if both component signatures are valid over the
// same bound message. There is no "either one is fine" mode here on purpose;
// that choice lives in the migration policy, not in the primitive.
func Verify(pk *PublicKey, ctx, msg, sig []byte) error {
	if len(ctx) > maxContextLen {
		return ErrContext
	}
	if len(sig) != SignatureSize {
		return ErrEncoding
	}
	if Suite(sig[0]) != SuiteEd25519MLDSA65 {
		return ErrSuite
	}
	m := boundMessage(pk, ctx, msg)
	edSig := sig[1 : 1+ed25519.SignatureSize]
	pqSig := sig[1+ed25519.SignatureSize:]

	// Evaluate both before deciding so timing does not reveal which half failed.
	okClassical := ed25519.Verify(pk.classical, m, edSig)
	okPQ := mldsa65.Verify(pk.pq, m, []byte(domain), pqSig)
	if okClassical && okPQ {
		return nil
	}
	return ErrSignature
}
