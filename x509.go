package jwker

import (
	"crypto/x509"
)

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
