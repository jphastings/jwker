package jwker_test

import (
	"io/ioutil"
	"testing"

	"github.com/jphastings/jwker"
)

func TestParsePEM(t *testing.T) {
	algos := []string{
		"ec", "rsa", "ed25519", "x25519",
		"ec.pub", "rsa.pub", "ed25519.pub", "x25519.pub",
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
				t.Fatal("failed to stringify JWK:", err)
			}

			if jwkStr != string(jwkBytes) {
				t.Error("output JWK does not match fixture:", jwkStr)
			}
		})
	}
}
