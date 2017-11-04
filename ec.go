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
    X: b64EncodeBigInt(key.X),
    Y: b64EncodeBigInt(key.Y),
  }
}

func processECPrivate(key *ecdsa.PrivateKey) *ECPrivate {
  return &ECPrivate{
    ECPublic: processECPublic(&key.PublicKey),
    D: b64EncodeBigInt(key.D),
  }
}
