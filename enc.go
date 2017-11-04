package main

import (
  "encoding/base64"
  "math/big"
)

func b64EncodeInt64(i64 int64) string {
  return b64EncodeBigInt(big.NewInt(i64))
}

func b64EncodeBigInt(bigInt *big.Int) string {
  return base64.RawURLEncoding.EncodeToString(bigInt.Bytes())
}