package main

import (
  "crypto/ecdsa"
  "crypto/rsa"
  "crypto/x509"
  "encoding/asn1"
  "encoding/base64"
  "encoding/json"
  "encoding/pem"
  "errors"
  "fmt"
  "io/ioutil"
  "os"
)

type RSAPublic struct {
  KeyType string `json:"kty"`
  Modulus string `json:"n"`
  PublicExponent string `json:"e"`
}

type ECPublic struct {
  KeyType string `json:"kty"`
  Curve string `json:"crv"`
  X string `json:"x"`
  Y string `json:"y"`
}

func main() {
  bytes, _ := ioutil.ReadAll(os.Stdin)
  pemBlock := getPemBlock(bytes)

  processBlock(pemBlock)
}

func getPemBlock(givenBytes []byte) *pem.Block {
  // Only get the first PEM block
  pemBlock, _ := pem.Decode(givenBytes)

  // TODO: not a PEM block
  if (false) {
    fmt.Fprintf(os.Stderr, "error: Data constains no PEM block.")
    os.Exit(1)
  }

  if (x509.IsEncryptedPEMBlock(pemBlock)) {
    fmt.Fprintf(os.Stderr, "error: The given file contains an encrypted PEM file. Please decrypt first.")
    os.Exit(2)
  }

  return pemBlock
}

func processBlock(pemBlock *pem.Block) {
  switch pemBlock.Type  {
  case "PUBLIC KEY":
    processPublicKey(pemBlock.Bytes)
  default:
    fmt.Fprintf(os.Stderr, "error: unsupported key type %q", pemBlock.Type)
    os.Exit(3)
  }
}

func processPublicKey(bytes []byte) {
  key, err := x509.ParsePKIXPublicKey(bytes)
  stopOnParseError(err)

  switch key := key.(type) {
  case *rsa.PublicKey:
    processRSAPublic(key)
  case *ecdsa.PublicKey:
    processECPublic(key)
  default:
    stopOnParseError(errors.New("Unknown key type"))
  }
}

func processRSAPublic(key *rsa.PublicKey) {
  jwk := &RSAPublic{
    KeyType: "RSA",
    Modulus: encodeValue(key.N),
    PublicExponent: encodeValue(key.E),
  }
  returnJWK(jwk)
}

func processECPublic(key *ecdsa.PublicKey) {
  jwk := &ECPublic{
    KeyType: "EC",
    Curve: key.Params().Name,
    X: encodeValue(key.X),
    Y: encodeValue(key.Y),
  }
  returnJWK(jwk)
}

func encodeValue(val interface{}) string {
  asn1Enc, err := asn1.Marshal(val)
  stopOnParseError(err)
  return base64.RawURLEncoding.EncodeToString(asn1Enc)
}

func stopOnParseError(err error) {
  if (err != nil) {
    fmt.Fprintf(os.Stderr, "error: could not parse key.", err)
    os.Exit(3)
  }
}

func returnJWK(jwk interface{}) {
  j, err := json.Marshal(jwk)

  if (err != nil) {
    fmt.Fprintf(os.Stderr, "error: could not render JSON.", err)
    os.Exit(4)
  }

  fmt.Print(string(j))
}
