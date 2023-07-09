package jwker

import (
	"encoding/json"
	"fmt"
)

type JWK struct {
	KeyType string `json:"kty"`

	// EC, Public
	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`

	// RSA, Public
	Modulus        string `json:"n,omitempty"`
	PublicExponent string `json:"e,omitempty"`

	// EC & RSA, Private
	D string `json:"d,omitempty"`

	// RSA, Private
	Prime1      string `json:"p,omitempty"`
	Prime2      string `json:"q,omitempty"`
	Exponent1   string `json:"dp,omitempty"`
	Exponent2   string `json:"dq,omitempty"`
	Coefficient string `json:"qi,omitempty"`
}

func (j *JWK) String() (string, error) {
	jwk, err := json.Marshal(j)
	if err != nil {
		return "", fmt.Errorf("could not render JSON: %v", err)
	}

	return string(jwk), nil
}

func ParseJWK(bytes []byte) (*JWK, error) {
	jwk := &JWK{}
	err := json.Unmarshal(bytes, jwk)
	if err != nil {
		return nil, fmt.Errorf("could not parse JWK: %v", err)
	}

	return jwk, nil
}
