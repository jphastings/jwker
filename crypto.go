package jwker

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PublicKeyToJWK converts any public key type created by the crypto x509 package
// into a JWK. This includes *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey,
// ed25519.PublicKey (not a pointer), or *ecdh.PublicKey (for X25519).
func PublicKeyToJWK(key any) (*JWK, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return fromRSAPublic(key), nil
	case *ecdsa.PublicKey:
		return fromECPublic(key), nil
	case ed25519.PublicKey:
		return fromEd25519Public(key), nil
	case *ecdh.PublicKey:
		return fromECDHPublic(key), nil
	default:
		return nil, fmt.Errorf("unknown public key type: %T", key)
	}
}

// PrivateKeyToJWK converts any private key type created by the crypto x509 package
// into a JWK. This includes *rsa.PublicKey, *ecdsa.PublicKey,
// ed25519.PublicKey (not a pointer), and *ecdh.PublicKey.
func PrivateKeyToJWK(key any) (*JWK, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return fromRSAPrivate(key), nil
	case *ecdsa.PrivateKey:
		return fromECPrivate(key), nil
	case ed25519.PrivateKey:
		return fromEd25519Private(key), nil
	case *ecdh.PrivateKey:
		return fromECDHPrivate(key), nil
	default:
		return nil, fmt.Errorf("unknown private key type: %T", key)
	}
}

func processPKIXPublicKey(bytes []byte) (*JWK, error) {
	key, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}

	return PublicKeyToJWK(key)
}

func processPKCS8PrivateKey(bytes []byte) (*JWK, error) {
	key, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	return PrivateKeyToJWK(key)
}

func (jwk *JWK) Key() (any, error) {
	toKeyFuncs := []func(*JWK) (any, bool, error){
		toRSAKey, toECKey, toECDHKey, toEd25519Key,
	}

	for _, toKey := range toKeyFuncs {
		key, isSuitable, err := toKey(jwk)
		if err != nil {
			return nil, err
		}
		if !isSuitable {
			continue
		}

		return key, nil
	}

	return nil, fmt.Errorf("unsupported JWK")
}

func (jwk *JWK) PEM() ([]byte, error) {
	key, err := jwk.Key()
	if err != nil {
		return nil, err
	}

	var block *pem.Block

	switch key := key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	case ed25519.PrivateKey, *ecdh.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	case *rsa.PrivateKey:
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	default:
		return nil, fmt.Errorf("unknown key type: %T", key)
	}

	return pem.EncodeToMemory(block), nil
}
