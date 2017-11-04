package main

import (
  "crypto/ecdsa"
)

type ECPublic struct {
  KeyType string `json:"kty"`
  Curve string `json:"crv"`
  X string `json:"x"`
  Y string `json:"y"`
}

func processECPublic(key *ecdsa.PublicKey) *ECPublic {
  return &ECPublic{
    KeyType: "EC",
    Curve: key.Params().Name,
    X: asn1b64Encode(key.X),
    Y: asn1b64Encode(key.Y),
  }
}
