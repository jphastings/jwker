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
    Modulus: b64EncodeBigInt(key.N),
    PublicExponent: b64EncodeInt64(int64(key.E)),
  }
}

func processRSAPrivate(key *rsa.PrivateKey) *RSAPrivate {
  return &RSAPrivate{
    RSAPublic: processRSAPublic(&key.PublicKey),
    PrivateExponent: b64EncodeBigInt(key.D),
    Prime1: b64EncodeBigInt(key.Primes[0]),
    Prime2: b64EncodeBigInt(key.Primes[1]),
    Exponent1: b64EncodeBigInt(key.Precomputed.Dp),
    Exponent2: b64EncodeBigInt(key.Precomputed.Dq),
    Coefficient: b64EncodeBigInt(key.Precomputed.Qinv),
  }
}