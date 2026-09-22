package hybrid

import (
	"crypto/ed25519"
	"errors"
)

// Policy describes how a chain moves from classical-only signatures to
// hybrid-only signatures without a flag day for every wallet at once.
//
//	height <  UpgradeOpen   : legacy Ed25519 only
//	UpgradeOpen <= height < Enforce : legacy or hybrid accepted
//	height >= Enforce       : hybrid only, legacy rejected
//
// The window between UpgradeOpen and Enforce is when accounts rotate. In
// practice it needs to be long (months), because exchanges and custodians
// move slowly and a stuck custodian is a stuck user.
type Policy struct {
	UpgradeOpen uint64
	Enforce     uint64
}

var (
	ErrLegacyRetired = errors.New("hybrid: legacy signatures no longer accepted at this height")
	ErrTooEarly      = errors.New("hybrid: hybrid signatures not yet accepted at this height")
	ErrPolicy        = errors.New("hybrid: invalid policy, Enforce must be >= UpgradeOpen")
)

func (p Policy) Validate() error {
	if p.Enforce < p.UpgradeOpen {
		return ErrPolicy
	}
	return nil
}

// Tx is the minimum a verifier needs. A real transaction would carry more,
// but signature handling only ever looks at these fields.
type Tx struct {
	Height    uint64
	SignBytes []byte

	// Exactly one of these pairs is set.
	LegacyKey ed25519.PublicKey
	LegacySig []byte
	HybridKey *PublicKey
	HybridSig []byte
}

// VerifyTx applies the policy for the height the transaction lands at.
func (p Policy) VerifyTx(chainID []byte, tx Tx) error {
	if err := p.Validate(); err != nil {
		return err
	}
	switch {
	case tx.HybridKey != nil:
		if tx.Height < p.UpgradeOpen {
			return ErrTooEarly
		}
		return Verify(tx.HybridKey, chainID, tx.SignBytes, tx.HybridSig)
	case tx.LegacyKey != nil:
		if tx.Height >= p.Enforce {
			return ErrLegacyRetired
		}
		if len(tx.LegacyKey) != ed25519.PublicKeySize || !ed25519.Verify(tx.LegacyKey, tx.SignBytes, tx.LegacySig) {
			return ErrSignature
		}
		return nil
	default:
		return ErrEncoding
	}
}
