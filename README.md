# Jwker

This is a command line tool to easily convert keys between the PEM and JWK file formats.

## Usage

Convert from PEM to JWK format:

```bash
jwker my-key.pem my-key.jwk
jwker my-key.pem | pbcopy
cat my-key.pem | jwker > my-key.jwk
```

A complete example for creating a new keypair, saving the public key as a JWK and the private key as a PEM, but with a passphrase:

```bash
openssl ecparam -genkey -name prime256v1 \
| tee >(openssl ec -pubout | jwker > key.pub.jwk) \
| openssl ec -aes256 -out key.prv.pem
```

Convert from JWK to PEM format:

```bash
jwker my-key.jwk my-key.pwm
jwker my-key.jwk | pbcopy
cat my-key.jwk | jwker
```

## Installation

If you have go installed:

```bash
go install github.com/jphastings/jwker/cmd/jwker@latest
```
