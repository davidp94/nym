package elgamal

import (
	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// todo: rename field names?
type ElGamalEncryption struct {
	a *BLS381.ECP
	b *BLS381.ECP
}

func Keygen(G *bpgroup.BpGroup) (*BLS381.BIG, *BLS381.ECP) {
	d := BLS381.Randomnum(G.Ord, G.Rng)
	gamma := BLS381.G1mul(G.Gen1, d)
	return d, gamma
}

// encrypts message in the form of h^m, where h is an element of G1
func Encrypt(G *bpgroup.BpGroup, gamma *BLS381.ECP, m *BLS381.BIG, h *BLS381.ECP) (ElGamalEncryption, *BLS381.BIG) {
	k := BLS381.Randomnum(G.Ord, G.Rng)
	a := BLS381.G1mul(G.Gen1, k)
	b := BLS381.G1mul(gamma, k) // b = (k * gamma)
	b.Add(BLS381.G1mul(h, m))   // b = (k * gamma) + (m * h)

	return ElGamalEncryption{a, b}, k
}

// returns decrypted message h^m
func Decrypt(G *bpgroup.BpGroup, d *BLS381.BIG, enc ElGamalEncryption) *BLS381.ECP {
	dec := BLS381.NewECP()
	dec.Copy(enc.b)
	dec.Sub(BLS381.G1mul(enc.a, d))
	return dec
}
