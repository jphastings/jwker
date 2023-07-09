package jwker

import (
	"crypto/ecdsa"
	"crypto/x509"
)

func ecPublic(key *ecdsa.PublicKey) *JWK {
	return &JWK{
		KeyType: "EC",
		Curve:   key.Params().Name,
		X:       b64EncodeBigInt(key.X),
		Y:       b64EncodeBigInt(key.Y),
	}
}

func ecPrivate(key *ecdsa.PrivateKey) *JWK {
	jwk := ecPublic(&key.PublicKey)
	jwk.D = b64EncodeBigInt(key.D)
	return jwk
}

func processECPrivate(bytes []byte) (*JWK, error) {
	key, err := x509.ParseECPrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	return ecPrivate(key), nil
}
