package jwker

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

func PublicKeyToJWK(key any) (*JWK, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return rsaPublic(key), nil
	case *ecdsa.PublicKey:
		return ecPublic(key), nil
	case ed25519.PublicKey:
		return ed25519Public(key), nil
	case *ecdh.PublicKey:
		return ecdhPublic(key), nil
	default:
		return nil, fmt.Errorf("unknown public key type: %T", key)
	}
}

func PrivateKeyToJWK(key any) (*JWK, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return rsaPrivate(key), nil
	case *ecdsa.PrivateKey:
		return ecPrivate(key), nil
	case ed25519.PrivateKey:
		return ed25519Private(key), nil
	case *ecdh.PrivateKey:
		return ecdhPrivate(key), nil
	default:
		return nil, fmt.Errorf("unknown private key type: %T", key)
	}
}
