package jwker_test

import (
	"io/ioutil"
	"testing"

	"github.com/jphastings/jwker"
	"github.com/stretchr/testify/assert"
)

func TestParsePEM(t *testing.T) {
	algos := []string{
		"ec", "rsa", "ed25519", "x25519",
		"ec.pub", "rsa.pub", "ed25519.pub", "x25519.pub",
		"ec-withparams", // OpenSSL creates a 'EC PARAMETERS' PEM block, this checks its correctly ignored
	}

	for _, algo := range algos {
		t.Run(algo, func(t *testing.T) {
			pemBytes, err := ioutil.ReadFile("test_data/" + algo + ".pem")
			if err != nil {
				t.Fatal("failed to read PEM fixture:", err)
			}
			jwkBytes, err := ioutil.ReadFile("test_data/" + algo + ".jwk")
			if err != nil {
				t.Fatal("failed to read JWK fixture:", err)
			}

			jwk, err := jwker.ParsePEM(pemBytes)
			if err != nil {
				t.Fatal("failed to convert PEM to JWK:", err)
			}
			jwkStr, err := jwk.String()
			if err != nil {
				t.Fatal("failed to marshal JWK:", err)
			}

			assert.JSONEq(t, string(jwkBytes), jwkStr)
		})
	}
}
