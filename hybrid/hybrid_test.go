package hybrid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

var chain = []byte("testnet-7")

func mustKey(t testing.TB) (*PublicKey, *PrivateKey) {
	t.Helper()
	pk, sk, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pk, sk
}

func TestRoundTrip(t *testing.T) {
	pk, sk := mustKey(t)
	msg := []byte("transfer 10 to alice")
	sig, err := sk.Sign(chain, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("sig size %d want %d", len(sig), SignatureSize)
	}
	if err := Verify(pk, chain, msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestTamperedMessage(t *testing.T) {
	pk, sk := mustKey(t)
	sig, _ := sk.Sign(chain, []byte("transfer 10 to alice"))
	if err := Verify(pk, chain, []byte("transfer 99 to alice"), sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v want ErrSignature", err)
	}
}

func TestEitherHalfBrokenFails(t *testing.T) {
	pk, sk := mustKey(t)
	msg := []byte("m")
	sig, _ := sk.Sign(chain, msg)

	for name, idx := range map[string]int{"ed25519": 5, "ml-dsa": 1 + 64 + 100} {
		bad := bytes.Clone(sig)
		bad[idx] ^= 0x01
		if err := Verify(pk, chain, msg, bad); err == nil {
			t.Errorf("flipping a bit in the %s half was accepted", name)
		}
	}
}

func TestContextSeparatesChains(t *testing.T) {
	pk, sk := mustKey(t)
	msg := []byte("m")
	sig, _ := sk.Sign([]byte("mainnet"), msg)
	if err := Verify(pk, []byte("testnet"), msg, sig); err == nil {
		t.Fatal("signature replayed across chains")
	}
}

// The Ed25519 half must not stand on its own as a signature over the raw message.
func TestStrippedClassicalHalfIsUseless(t *testing.T) {
	pk, sk := mustKey(t)
	msg := []byte("m")
	sig, _ := sk.Sign(chain, msg)
	edHalf := sig[1 : 1+ed25519.SignatureSize]
	if ed25519.Verify(pk.Classical(), msg, edHalf) {
		t.Fatal("classical half verifies alone over the raw message")
	}
}

func TestSignatureBoundToKey(t *testing.T) {
	_, sk := mustKey(t)
	other, _ := mustKey(t)
	sig, _ := sk.Sign(chain, []byte("m"))
	if err := Verify(other, chain, []byte("m"), sig); err == nil {
		t.Fatal("signature verified under a different key")
	}
}

func TestSeedDeterminism(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, SeedSize)
	a, _, _ := NewKeyFromSeed(seed)
	b, _, _ := NewKeyFromSeed(seed)
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("same seed gave different keys")
	}
	if _, _, err := NewKeyFromSeed(seed[:31]); !errors.Is(err, ErrShortSeed) {
		t.Fatal("short seed accepted")
	}
}

func TestPublicKeyEncoding(t *testing.T) {
	pk, _ := mustKey(t)
	enc := pk.Bytes()
	if len(enc) != PublicKeySize {
		t.Fatalf("pk size %d", len(enc))
	}
	back, err := ParsePublicKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.Address() != pk.Address() {
		t.Fatal("address changed after round trip")
	}
	enc[0] = 0x7f
	if _, err := ParsePublicKey(enc); !errors.Is(err, ErrSuite) {
		t.Fatalf("got %v want ErrSuite", err)
	}
	if _, err := ParsePublicKey(enc[:10]); !errors.Is(err, ErrEncoding) {
		t.Fatalf("got %v want ErrEncoding", err)
	}
}

func TestWrongSuiteByteOnSignature(t *testing.T) {
	pk, sk := mustKey(t)
	sig, _ := sk.Sign(chain, []byte("m"))
	sig[0] = 0x02
	if err := Verify(pk, chain, []byte("m"), sig); !errors.Is(err, ErrSuite) {
		t.Fatalf("got %v want ErrSuite", err)
	}
}

func TestLongContextRejected(t *testing.T) {
	_, sk := mustKey(t)
	if _, err := sk.Sign(make([]byte, 256), []byte("m")); !errors.Is(err, ErrContext) {
		t.Fatal("256 byte context accepted")
	}
}

func TestMigrationPolicy(t *testing.T) {
	p := Policy{UpgradeOpen: 100, Enforce: 200}
	msg := []byte("tx")

	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	legacy := Tx{SignBytes: msg, LegacyKey: edPub, LegacySig: ed25519.Sign(edPriv, msg)}

	hpk, hsk := mustKey(t)
	hsig, _ := hsk.Sign(chain, msg)
	hyb := Tx{SignBytes: msg, HybridKey: hpk, HybridSig: hsig}

	cases := []struct {
		name   string
		tx     Tx
		height uint64
		want   error
	}{
		{"legacy before window", legacy, 50, nil},
		{"hybrid before window", hyb, 50, ErrTooEarly},
		{"legacy in window", legacy, 150, nil},
		{"hybrid in window", hyb, 150, nil},
		{"legacy after enforce", legacy, 200, ErrLegacyRetired},
		{"hybrid after enforce", hyb, 250, nil},
	}
	for _, c := range cases {
		c.tx.Height = c.height
		if err := p.VerifyTx(chain, c.tx); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	if err := (Policy{UpgradeOpen: 10, Enforce: 5}).Validate(); !errors.Is(err, ErrPolicy) {
		t.Error("inverted policy accepted")
	}
}

func BenchmarkSign(b *testing.B) {
	_, sk := mustKey(b)
	msg := make([]byte, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sk.Sign(chain, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	pk, sk := mustKey(b)
	msg := make([]byte, 256)
	sig, _ := sk.Sign(chain, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(pk, chain, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519VerifyBaseline(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := make([]byte, 256)
	sig := ed25519.Sign(priv, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, msg, sig)
	}
}
