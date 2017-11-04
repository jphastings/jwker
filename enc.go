package main

import (
  "encoding/asn1"
  "encoding/base64"
)

func asn1b64Encode(val interface{}) string {
  asn1Enc, err := asn1.Marshal(val)
  stopOnParseError(err)
  return base64.RawURLEncoding.EncodeToString(asn1Enc)
}
