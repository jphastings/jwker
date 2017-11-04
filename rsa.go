package main

import (
  "crypto/rsa"
)

type RSAPublic struct {
  KeyType string `json:"kty"`
  Modulus string `json:"n"`
  PublicExponent string `json:"e"`
}

func processRSAPublic(key *rsa.PublicKey) *RSAPublic {
  return &RSAPublic{
    KeyType: "RSA",
    Modulus: asn1b64Encode(key.N),
    PublicExponent: asn1b64Encode(key.E),
  }
}

