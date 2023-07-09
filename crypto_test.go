package jwker_test

import (
	"io/ioutil"
	"testing"

	"github.com/jphastings/jwker"
	"github.com/stretchr/testify/assert"
)

func TestPEM(t *testing.T) {
	algos := []string{
		"ec", "rsa", "ed25519", "x25519",
		"ec.pub", "rsa.pub", "ed25519.pub", "x25519.pub",
	}

	for _, algo := range algos {
		t.Run(algo, func(t *testing.T) {
			jwkBytes, err := ioutil.ReadFile("test_data/" + algo + ".jwk")
			if err != nil {
				t.Fatal("failed to read JWK fixture:", err)
			}
			pemBytes, err := ioutil.ReadFile("test_data/" + algo + ".pem")
			if err != nil {
				t.Fatal("failed to read PEM fixture:", err)
			}

			jwk, err := jwker.ParseJWK(jwkBytes)
			if err != nil {
				t.Fatal("failed to unmarshal JWK:", err)
			}
			pem, err := jwk.PEM()
			if err != nil {
				t.Fatal("failed to convert JWK to PEM:", err)
			}

			assert.Equal(t, string(pemBytes), string(pem), "output PEM does not match fixture")
		})
	}
}
