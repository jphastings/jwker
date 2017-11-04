package main

import (
  "crypto/ecdsa"
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
)

func pemToJwk(pemBytes []byte) string {
  keyStruct := processBlock(pemBytes)
  return structToJWK(keyStruct)
}

func findPemBlock(pemBytes []byte) (*pem.Block, []byte) {
  // Only get the first PEM block
  pemBlock, rest := pem.Decode(pemBytes)

  if pemBlock == nil {
    throwParseError("invalid PEM file format.")
  }

  if (x509.IsEncryptedPEMBlock(pemBlock)) {
    throwParseError("the given PEM file is encrypted. Please decrypt first.")
  }

  return pemBlock, rest
}

func processBlock(pemBytes []byte) interface{} {
  pemBlock, rest := findPemBlock(pemBytes)

  var keyStruct interface{}

  switch pemBlock.Type {
  case "PUBLIC KEY":
    keyStruct = processPublicKey(pemBlock.Bytes)
  case "RSA PRIVATE KEY":
    key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
    stopOnParseError(err)

    keyStruct = processRSAPrivate(key)
  case "EC PARAMETERS":
    // The EC PARAMETERS section appears to not be needed:
    ecKey, _ := findPemBlock(rest)

    if ecKey.Type != "EC PRIVATE KEY" {
      throwParseError("unsupported EC PEM format.")
    }

    key, err := x509.ParseECPrivateKey(ecKey.Bytes)
    stopOnParseError(err)

    keyStruct = processECPrivate(key)
  default:
    throwParseError("unsupported PEM type.")
  }

  return keyStruct
}

func processPublicKey(bytes []byte) interface{} {
  key, err := x509.ParsePKIXPublicKey(bytes)
  stopOnParseError(err)

  var keyStruct interface{}

  switch key := key.(type) {
  case *rsa.PublicKey:
    keyStruct = processRSAPublic(key)
  case *ecdsa.PublicKey:
    keyStruct = processECPublic(key)
  default:
    throwParseError("Unknown key type.")
  }

  return keyStruct
}