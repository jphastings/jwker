package main

import (
  "fmt"
  "encoding/json"
  "os"
)

type JWK struct {
  KeyType string `json:"kty"`
}

func JwkToPem(jwkBytes []byte) string {
  throwParseError("JWK parsing is not implemented yet :(")
  return ""
}

func structToJWK(keyStruct interface{}) string {
  jwk, err := json.Marshal(keyStruct)

  if (err != nil) {
    fmt.Fprintf(os.Stderr, "error: could not render JSON (%v)", err)
    os.Exit(4)
  }

  return string(jwk)
}
