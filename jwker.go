package main

import (
  "fmt"
  "io/ioutil"
  "os"
)

func main() {
  bytes, _ := ioutil.ReadAll(os.Stdin)

  switch bytes[0] {
  case 45:
    fmt.Print(pemToJwk(bytes))
  case 123:
    fmt.Print(jwkToPem(bytes))
  default:
    throwParseError("unknown input file format")
  }
}

func throwParseError(message string) {
  fmt.Fprintf(os.Stderr, "Could not parse key: %v\n", message)
  os.Exit(1)
}

func stopOnParseError(err error) {
  if (err != nil) {
    throwParseError(err.Error())
  }
}
