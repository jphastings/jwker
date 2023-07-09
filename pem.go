package jwker

import (
	"encoding/pem"
	"fmt"
)

func ParsePEM(pemBytes []byte) (*JWK, error) {
	for len(pemBytes) > 0 {
		pemBlock, rest := pem.Decode(pemBytes)
		if pemBlock == nil {
			return nil, fmt.Errorf("invalid PEM file")
		}
		pemBytes = rest

		pr, ok := blockProcessors[pemBlock.Type]
		if !ok {
			return nil, fmt.Errorf("unsupported PEM block type: %s", pemBlock.Type)
		}

		jwk, err := pr(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		if jwk == nil {
			continue
		}
		return jwk, nil
	}

	return nil, fmt.Errorf("no supported PEM block found")
}

type processor func([]byte) (*JWK, error)

var skipBlock processor = func([]byte) (*JWK, error) { return nil, nil }

var blockProcessors = map[string]processor{
	"PUBLIC KEY":      processPKIXPublicKey,
	"PRIVATE KEY":     processPKCS8PrivateKey,
	"RSA PRIVATE KEY": processRSAPrivate,
	"EC PARAMETERS":   skipBlock,
	"EC PRIVATE KEY":  processECPrivate,
}
