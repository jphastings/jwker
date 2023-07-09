package jwker

import (
	"crypto/ecdh"
	"encoding/base64"
)

func fromECDHPublic(key *ecdh.PublicKey) *JWK {
	return &JWK{
		KeyType: "OKP",
		Curve:   "X25519",
		X:       base64.RawURLEncoding.EncodeToString(key.Bytes()),
	}
}

func fromECDHPrivate(key *ecdh.PrivateKey) *JWK {
	jwk := fromECDHPublic(key.PublicKey())
	jwk.D = base64.RawURLEncoding.EncodeToString(key.Bytes())

	return jwk
}

func toECDHKey(jwk *JWK) (any, bool, error) {
	if jwk.KeyType != "OKP" || jwk.Curve != "X25519" {
		return nil, false, nil
	}

	if jwk.D == "" {
		x, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, false, err
		}

		pub, err := ecdh.X25519().NewPublicKey(x)
		return pub, true, err
	} else {
		d, err := base64.RawURLEncoding.DecodeString(jwk.D)
		if err != nil {
			return nil, false, err
		}

		prv, err := ecdh.X25519().NewPrivateKey(d)
		return prv, true, err
	}
}
