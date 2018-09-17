package elgamal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

func TestElGamalKeygen(t *testing.T) {
	G := bpgroup.New()
	d, gamma := Keygen(G)

	assert.True(t, gamma.Equals(BLS381.G1mul(G.Gen1, d)), "Gamma should be equal to g1 * d")
}

func TestElGamalEncryption(t *testing.T) {
	G := bpgroup.New()
	_, gamma := Keygen(G)

	t1 := BLS381.Randomnum(G.Ord, G.Rng)
	h := BLS381.G1mul(G.Gen1, t1) // random h
	m := BLS381.Randomnum(G.Ord, G.Rng)

	enc, k := Encrypt(G, gamma, m, h)

	assert.True(t, enc.A.Equals(BLS381.G1mul(G.Gen1, k)), "a should be equal to g1^k")

	tmp := BLS381.G1mul(gamma, k) // b = (k * gamma)
	tmp.Add(BLS381.G1mul(h, m))   // b = (k * gamma) + (m * h)

	assert.True(t, enc.B.Equals(tmp), "b should be equal to (k * gamma) + (m * h)")
}

func TestElGamalDecryption(t *testing.T) {
	G := bpgroup.New()
	d, gamma := Keygen(G)

	t1 := BLS381.Randomnum(G.Ord, G.Rng)
	h := BLS381.G1mul(G.Gen1, t1) // random h
	m := BLS381.Randomnum(G.Ord, G.Rng)
	hm := BLS381.G1mul(h, m)

	enc, _ := Encrypt(G, gamma, m, h)
	dec := Decrypt(G, d, enc)

	assert.True(t, dec.Equals(hm), "Original message should be recovered")
}
