package jwker

import (
	"crypto/ed25519"
	"encoding/base64"
)

func fromEd25519Public(key ed25519.PublicKey) *JWK {
	return &JWK{
		KeyType: "OKP",
		Curve:   "Ed25519",
		X:       base64.RawURLEncoding.EncodeToString(key),
	}
}

func fromEd25519Private(key ed25519.PrivateKey) *JWK {
	jwk := fromEd25519Public(key.Public().(ed25519.PublicKey))
	jwk.D = base64.RawURLEncoding.EncodeToString(key)

	return jwk
}

func toEd25519Key(jwk *JWK) (any, bool, error) {
	if jwk.KeyType != "OKP" || jwk.Curve != "Ed25519" {
		return nil, false, nil
	}

	if jwk.D == "" {
		x, err := base64.RawURLEncoding.DecodeString(jwk.X)
		return ed25519.PublicKey(x), true, err
	} else {
		d, err := base64.RawURLEncoding.DecodeString(jwk.D)
		return ed25519.PrivateKey(d), true, err
	}
}
