package jwker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
)

func fromECPublic(key *ecdsa.PublicKey) *JWK {
	return &JWK{
		KeyType: "EC",
		Curve:   key.Params().Name,
		X:       b64EncodeBigInt(key.X),
		Y:       b64EncodeBigInt(key.Y),
	}
}

func fromECPrivate(key *ecdsa.PrivateKey) *JWK {
	jwk := fromECPublic(&key.PublicKey)
	jwk.D = b64EncodeBigInt(key.D)
	return jwk
}

func processECPrivate(bytes []byte) (*JWK, error) {
	key, err := x509.ParseECPrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	return fromECPrivate(key), nil
}

func toECKey(jwk *JWK) (any, bool, error) {
	if jwk.KeyType != "EC" {
		return nil, false, nil
	}

	pubKey := ecdsa.PublicKey{}
	switch jwk.Curve {
	case "P-256":
		pubKey.Curve = elliptic.P256()
	default:
		return nil, false, nil
	}

	pubArgs, ok := decodeAll(jwk.X, jwk.Y)
	if !ok {
		return nil, false, nil
	}
	pubKey.X = pubArgs[0]
	pubKey.Y = pubArgs[1]

	prvArgs, ok := decodeAll(jwk.D)
	if !ok {
		return &pubKey, true, nil
	}

	return &ecdsa.PrivateKey{
		PublicKey: pubKey,
		D:         prvArgs[0],
	}, true, nil
}
