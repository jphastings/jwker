package main

import (
  "crypto/ecdsa"
)

type ECPublic struct {
  *JWK
  Curve string `json:"crv"`
  X string `json:"x"`
  Y string `json:"y"`
}

type ECPrivate struct {
  *ECPublic
  D string `json:"d"`
}

func processECPublic(key *ecdsa.PublicKey) *ECPublic {
  return &ECPublic{
    JWK: &JWK{KeyType: "EC"},
    Curve: key.Params().Name,
    X: asn1b64Encode(key.X),
    Y: asn1b64Encode(key.Y),
  }
}

func processECPrivate(key *ecdsa.PrivateKey) *ECPrivate {
  return &ECPrivate{
    ECPublic: processECPublic(&key.PublicKey),
    D: asn1b64Encode(key.D),
  }
}
