package main

import (
  "crypto/rsa"
)

type RSAPublic struct {
  *JWK
  Modulus string `json:"n"`
  PublicExponent string `json:"e"`
}

type RSAPrivate struct {
  *RSAPublic
  PrivateExponent string `json:"d"`
  Prime1 string `json:"p"`
  Prime2 string `json:"q"`
  Exponent1 string `json:"dp"`
  Exponent2 string `json:"dq"`
  Coefficient string `json:"qi"`
}

func processRSAPublic(key *rsa.PublicKey) *RSAPublic {
  return &RSAPublic{
    JWK: &JWK{KeyType: "RSA"},
    Modulus: asn1b64Encode(key.N),
    PublicExponent: asn1b64Encode(key.E),
  }
}

func processRSAPrivate(key *rsa.PrivateKey) *RSAPrivate {
  return &RSAPrivate{
    RSAPublic: processRSAPublic(&key.PublicKey),
    PrivateExponent: asn1b64Encode(key.D),
    Prime1: asn1b64Encode(key.Primes[0]),
    Prime2: asn1b64Encode(key.Primes[1]),
    Exponent1: asn1b64Encode(key.Precomputed.Dp),
    Exponent2: asn1b64Encode(key.Precomputed.Dq),
    Coefficient: asn1b64Encode(key.Precomputed.Qinv),
  }
}