package jwker

import (
	"crypto/rsa"
	"crypto/x509"
)

func rsaPublic(key *rsa.PublicKey) *JWK {
	return &JWK{
		KeyType:        "RSA",
		Modulus:        b64EncodeBigInt(key.N),
		PublicExponent: b64EncodeInt64(int64(key.E)),
	}
}

func rsaPrivate(key *rsa.PrivateKey) *JWK {
	jwk := rsaPublic(&key.PublicKey)
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

	return rsaPrivate(key), nil
}
