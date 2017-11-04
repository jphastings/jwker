package main

import (
  "fmt"
  "io/ioutil"
  "os"
)

const version = "v0.1.0"

func usage() {
  fmt.Print(
    fmt.Sprintf("jwker: a PEM -> JWK conversion tool (%v)\n", version) +
    `
Example usage:
  jwker key.pem > key.jwk
  cat key.pem | jwker > key.jwk

Create a new keypair, save the public key as a JWK and
the private key as a PEM, but with a passphrase:

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
    fmt.Print(PemToJwk(bytes))
  case 123:
    fmt.Print(JwkToPem(bytes))
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
