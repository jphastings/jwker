package main

import (
  "fmt"
  "encoding/json"
  "os"
)

func jwkToPem(jwkBytes []byte) string {
  return "Not implemented"
}

func structToJWK(keyStruct interface{}) string {
  jwk, err := json.Marshal(keyStruct)

  if (err != nil) {
    fmt.Fprintf(os.Stderr, "error: could not render JSON.", err)
    os.Exit(4)
  }

  return string(jwk)
}
