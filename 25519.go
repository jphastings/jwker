package jwker

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
)

func ecBytes(crv string, bytes []byte) *JWK {
	return &JWK{
		KeyType: "OKP",
		Curve:   crv,
		X:       base64.RawURLEncoding.EncodeToString(bytes),
	}
}

func ecdhPublic(key *ecdh.PublicKey) *JWK        { return ecBytes("X25519", key.Bytes()) }
func ecdhPrivate(key *ecdh.PrivateKey) *JWK      { return ecBytes("X25519", key.Bytes()) }
func ed25519Public(key ed25519.PublicKey) *JWK   { return ecBytes("Ed25519", key) }
func ed25519Private(key ed25519.PrivateKey) *JWK { return ecBytes("Ed25519", key) }
