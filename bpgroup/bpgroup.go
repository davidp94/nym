package bpgroup

import (
	"crypto/rand"

	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// todo: consider dynamically allowing different curves?
type BpGroup struct {
	Gen1 *BLS381.ECP
	Gen2 *BLS381.ECP2
	Ord  *BLS381.BIG
	Rng  *amcl.RAND
}

func New() *BpGroup {
	rng := amcl.NewRAND()

	// amcl suggests using at least 128 bytes of entropy.
	// todo: is 256 enough for our needs?
	n := 256
	raw, err := generateRandomBytes(n)
	if err != nil {
		panic(err)
	}
	rng.Seed(n, raw)

	b := BpGroup{
		Gen1: BLS381.ECP_generator(),
		Gen2: BLS381.ECP2_generator(),
		Ord:  BLS381.NewBIGints(BLS381.CURVE_Order),
		Rng:  rng,
	}
	return &b
}

func (b *BpGroup) Pair(g1 *BLS381.ECP, g2 *BLS381.ECP2) *BLS381.FP12 {
	return BLS381.Fexp(BLS381.Ate(g2, g1))
}

// Returns slice of bytes of specified size of cryptographically secure random numbers.
// Refer to https://golang.org/pkg/crypto/rand/ for details regarding sources of entropy
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
