package jwker

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
)

func fromRSAPublic(key *rsa.PublicKey) *JWK {
	return &JWK{
		KeyType:        "RSA",
		Modulus:        b64EncodeBigInt(key.N),
		PublicExponent: b64EncodeBigInt(big.NewInt(int64(key.E))),
	}
}

func fromRSAPrivate(key *rsa.PrivateKey) *JWK {
	jwk := fromRSAPublic(&key.PublicKey)
	jwk.D = b64EncodeBigInt(key.D)
	jwk.Prime1 = b64EncodeBigInt(key.Primes[0])
	jwk.Prime2 = b64EncodeBigInt(key.Primes[1])
	jwk.Exponent1 = b64EncodeBigInt(key.Precomputed.Dp)
	jwk.Exponent2 = b64EncodeBigInt(key.Precomputed.Dq)
	jwk.Coefficient = b64EncodeBigInt(key.Precomputed.Qinv)

	return jwk
}

func processRSAPrivate(bytes []byte) (*JWK, error) {
	key, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	return fromRSAPrivate(key), nil
}

func toRSAKey(jwk *JWK) (any, bool, error) {
	if jwk.KeyType != "RSA" {
		return nil, false, nil
	}

	pubArgs, ok := decodeAll(jwk.Modulus, jwk.PublicExponent)
	if !ok {
		return nil, false, nil
	}
	pubKey := rsa.PublicKey{
		N: pubArgs[0],
		E: int(pubArgs[1].Int64()),
	}

	prvArgs, ok := decodeAll(jwk.D, jwk.Prime1, jwk.Prime2)
	if !ok {
		return &pubKey, true, nil
	}

	return &rsa.PrivateKey{
		PublicKey: pubKey,
		D:         prvArgs[0],
		Primes:    []*big.Int{prvArgs[1], prvArgs[2]},
	}, true, nil
}
