package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/jphastings/jwker"
)

const version = "v0.2.0"

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
	bytes, err := loadFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to load file: %v\n", err)
		os.Exit(1)
	}

	switch bytes[0] {
	case 45: // ASCII "-"
		jwk, err := jwker.ParsePEM(bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to parse PEM: %v\n", err)
			os.Exit(1)
		}
		str, err := jwk.String()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Internal issue with stringifying JWK: %v\n", err)
			os.Exit(2)
		}
		fmt.Print(str)
	case 123: // ASCII "{"
		fmt.Fprintln(os.Stderr, "JWK to PEM conversion isn't supported yet)")
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "Unknown file format (starting with '%s')\n", string(bytes[0]))
		os.Exit(1)
	}

	os.Exit(0)
}

func loadFile() ([]byte, error) {
	file := os.Stdin
	if len(os.Args) > 1 {
		namedFile, err := os.Open(os.Args[1])
		if err != nil {
			return nil, err
		}
		file = namedFile
	}

	fileStat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if fileStat.Size() == 0 {
		usage()
	}

	return ioutil.ReadAll(file)
}
