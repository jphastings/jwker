package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jphastings/jwker"
)

func usage(exitCode int) {
	fmt.Print(`jwker: a PEM -> JWK conversion tool

Example usage:
  jwker key.pem > key.jwk
  cat key.pem | jwker > key.jwk

Create a new keypair, save the public key as a JWK and
the private key as a PEM, but with a passphrase:

  openssl ecparam -genkey -name prime256v1 \
  | tee >(openssl ec -pubout | jwker > key.pub.jwk) \
  | openssl ec -aes256 -out key.prv.pem
`)
	os.Exit(exitCode)
}

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

func main() {
	var in *os.File
	var out *os.File
	var err error

	switch len(os.Args) {
	case 1:
		in = os.Stdin
		out = os.Stdout
	case 2:
		out = os.Stdout
		in, err = os.Open(os.Args[1])
		check(err)
	case 3:
		in, err = os.Open(os.Args[1])
		check(err)
		out, err = os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		check(err)
	default:
		usage(1)
	}

	fileStat, err := in.Stat()
	check(err)
	if fileStat.Size() == 0 {
		usage(-1)
	}

	bytes, err := io.ReadAll(in)
	check(err)

	switch bytes[0] {
	case 45: // ASCII "-"
		jwk, err := jwker.ParsePEM(bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to parse PEM: %v\n", err)
			os.Exit(1)
		}
		jwkStr, err := jwk.String()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Internal issue: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(out, "%s", jwkStr)
	case 123: // ASCII "{"
		jwk, err := jwker.ParseJWK(bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to parse JWK: %v\n", err)
			os.Exit(1)
		}
		pem, err := jwk.PEM()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Internal issue: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(out, "%s", pem)
	default:
		fmt.Fprintf(os.Stderr, "Unknown file format (starting with '%s')\n", string(bytes[0]))
		os.Exit(1)
	}

	os.Exit(0)
}
