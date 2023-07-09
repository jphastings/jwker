package jwker

import (
	"encoding/base64"
	"math/big"
)

func b64EncodeBigInt(bigInt *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(bigInt.Bytes())
}

func b64DecodeBigInt(str string) (*big.Int, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return big.NewInt(0).SetBytes(bytes), nil
}

func decodeAll(args ...string) ([]*big.Int, bool) {
	bigInts := make([]*big.Int, len(args))
	for i, arg := range args {
		if arg == "" {
			return nil, false
		}

		bigInt, err := b64DecodeBigInt(arg)
		if err != nil {
			return nil, false
		}
		bigInts[i] = bigInt
	}
	return bigInts, true
}
