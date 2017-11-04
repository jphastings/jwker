package main

import (
  "fmt"
  "io/ioutil"
  "os"
)

func usage() {
  fmt.Print(`jwker: a PEM <-> JWK conversion tool

Example usage:
  jwker key.pem > key.jwk
  jwker key.jwk > key.pem

Create a new keypair, save the public key to a JWK and
save the private key as a PEM, but with a passphrase:

  openssl ecparam -genkey -name prime256v1 \
  | tee >(openssl ec -pubout | jwker > key.pub.jwk) \
  | openssl ec -aes256 -out key.prv.pem
`)
  os.Exit(-1)
}

func main() {
  bytes := loadFile()

  switch bytes[0] {
  case 45:
    fmt.Print(pemToJwk(bytes))
  case 123:
    fmt.Print(jwkToPem(bytes))
  default:
    fmt.Print(bytes[0])
    throwParseError("unknown input file format")
  }

  os.Exit(0)
}

func loadFile() []byte {
  file := os.Stdin
  if len(os.Args) > 1 {
    namedFile, err := os.Open(os.Args[1])
    stopOnParseError(err)
    file = namedFile
  }

  fileStat, err := file.Stat()
  stopOnParseError(err)
  if fileStat.Size() == 0 {
    usage()
  }

  bytes, err := ioutil.ReadAll(file)
  stopOnParseError(err)
  return bytes
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
