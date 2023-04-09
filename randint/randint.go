package randint

import (
	"crypto/rand"
	"math/big"
	crand "math/rand"
)

func IntN(max int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return crand.Intn(max)
	}
	return int(nBig.Int64())
}
