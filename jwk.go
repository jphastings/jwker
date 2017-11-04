package main

import (
  "fmt"
  "encoding/json"
  "os"
)

type JWK struct {
  KeyType string `json:"kty"`
}

func jwkToPem(jwkBytes []byte) string {
  throwParseError("JWK parsing is not implemented yet :(")
  return ""
}

func structToJWK(keyStruct interface{}) string {
  jwk, err := json.Marshal(keyStruct)

  if (err != nil) {
    fmt.Fprintf(os.Stderr, "error: could not render JSON.", err)
    os.Exit(4)
  }

  return string(jwk)
}
