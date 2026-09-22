// hpqsig is a small CLI for poking at hybrid keys and signatures.
//
//	hpqsig keygen            prints a hex seed and the matching public key
//	hpqsig sign SEED CTX MSG prints a hex signature
//	hpqsig verify PK CTX MSG SIG
//	hpqsig sizes             prints encoded sizes next to plain Ed25519
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/evdatsion/hybrid-pq-sig/hybrid"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		seed := make([]byte, hybrid.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			die(err)
		}
		pk, _, err := hybrid.NewKeyFromSeed(seed)
		if err != nil {
			die(err)
		}
		addr := pk.Address()
		fmt.Printf("seed    %x\naddress %x\npubkey  %x\n", seed, addr, pk.Bytes())
	case "sign":
		need(5)
		seed := unhex(os.Args[2])
		_, sk, err := hybrid.NewKeyFromSeed(seed)
		if err != nil {
			die(err)
		}
		sig, err := sk.Sign([]byte(os.Args[3]), []byte(os.Args[4]))
		if err != nil {
			die(err)
		}
		fmt.Printf("%x\n", sig)
	case "verify":
		need(6)
		pk, err := hybrid.ParsePublicKey(unhex(os.Args[2]))
		if err != nil {
			die(err)
		}
		if err := hybrid.Verify(pk, []byte(os.Args[3]), []byte(os.Args[4]), unhex(os.Args[5])); err != nil {
			die(err)
		}
		fmt.Println("ok")
	case "sizes":
		fmt.Printf("%-22s %8s %10s\n", "scheme", "pubkey", "signature")
		fmt.Printf("%-22s %8d %10d\n", "Ed25519", ed25519.PublicKeySize, ed25519.SignatureSize)
		fmt.Printf("%-22s %8d %10d\n", "Ed25519 + ML-DSA-65", hybrid.PublicKeySize, hybrid.SignatureSize)
	default:
		usage()
	}
}

func need(n int) {
	if len(os.Args) < n {
		usage()
	}
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		die(err)
	}
	return b
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hpqsig keygen | sign SEED CTX MSG | verify PK CTX MSG SIG | sizes")
	os.Exit(2)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
