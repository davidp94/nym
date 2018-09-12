package coconut

//  todo: consider renaming all functions

import (
	"errors"

	"github.com/milagro-crypto/amcl/version3/go/amcl"

	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// todo: get proper names for below
type SignerProof struct {
	c  *BLS381.BIG
	rr *BLS381.BIG
	rk []*BLS381.BIG
	rm []*BLS381.BIG
}

// generate challenge as in python implementation, apart from how strings are obtained from G1 and G2 elems
// todo: update once tostring is exposed
func constructChallenge(G1Gen *BLS381.ECP, G2Gen *BLS381.ECP2, slices [][]*BLS381.ECP) *BLS381.BIG {
	// first part is G1Gen,G2Gen,...
	cs := stringFromG1(G1Gen) + "," + stringFromG2(G2Gen)
	for _, slice := range slices {
		for _, item := range slice {
			cs += ("," + stringFromG1(item))
		}
	}
	c, err := HashStringToBig(amcl.SHA256, cs)
	if err != nil {
		panic(err)
	}
	return c
}

// todo: as before add concurrency once basic version is functional
func ConstructSignerProof(params *Params, gamma *BLS381.ECP, encs []elgamal.ElGamalEncryption, cm *BLS381.ECP, k []*BLS381.BIG, r *BLS381.BIG, public_m []*BLS381.BIG, private_m []*BLS381.BIG) (*SignerProof, error) {
	attributes := append(private_m, public_m...)
	G := params.G
	if len(encs) != len(k) || len(encs) != len(private_m) {
		return nil, errors.New("Invalid ciphertexts provided")
	}
	if len(attributes) > len(params.hs) {
		return nil, errors.New("More than specified attributes provided")
	}

	// witnesses creation
	wr := BLS381.Randomnum(G.Ord, G.Rng)
	wk := make([]*BLS381.BIG, len(k))
	wm := make([]*BLS381.BIG, len(attributes))

	for i := range k {
		wk[i] = BLS381.Randomnum(G.Ord, G.Rng)
	}
	for i := range attributes {
		wm[i] = BLS381.Randomnum(G.Ord, G.Rng)
	}

	h, err := hashStringToG1(amcl.SHA256, stringFromG1(cm))
	if err != nil {
		panic(err)
	}

	// witnesses commitments
	Aw := make([]*BLS381.ECP, len(wk))
	Bw := make([]*BLS381.ECP, len(private_m))
	var Cw *BLS381.ECP

	for i := range wk {
		Aw[i] = BLS381.G1mul(G.Gen1, wk[i])
	}
	for i := range private_m {
		Bw[i] = BLS381.G1mul(h, wm[i])        // Bw[i] = (h * wm[i])
		Bw[i].Add(BLS381.G1mul(gamma, wk[i])) // Bw[i] = (wk[i] * gamma) + (h * wm[i])
	}

	Cw = BLS381.G1mul(G.Gen1, wr)
	for i := range attributes {
		Cw.Add(BLS381.G1mul(params.hs[i], wm[i]))
	}

	c := constructChallenge(G.Gen1, G.Gen2, [][]*BLS381.ECP{{cm, h, Cw}, params.hs, Aw, Bw})

	// responses
	rr := wr.Minus(BLS381.Modmul(c, r, G.Ord))
	// todo: add order to each result to ensure positive results?
	rr.Mod(G.Ord)

	rk := make([]*BLS381.BIG, len(wk))
	for i := range wk {
		rk[i] = wk[i].Minus(BLS381.Modmul(c, k[i], G.Ord))
		rk[i].Mod(G.Ord)
	}

	rm := make([]*BLS381.BIG, len(wm))
	for i := range wm {
		rm[i] = wm[i].Minus(BLS381.Modmul(c, attributes[i], G.Ord))
		rm[i].Mod(G.Ord)
	}

	return &SignerProof{
			c:  c,
			rr: rr,
			rk: rk,
			rm: rm},
		nil
}

// todo: as before add concurrency once basic version is functional
func VerifySignerProof(params *Params, gamma *BLS381.ECP, encs []elgamal.ElGamalEncryption, cm *BLS381.ECP, proof *SignerProof) bool {
	if len(encs) != len(proof.rk) {
		return false
	}
	h, err := hashStringToG1(amcl.SHA256, stringFromG1(cm))
	if err != nil {
		panic(err)
	}

	Aw := make([]*BLS381.ECP, len(proof.rk))
	Bw := make([]*BLS381.ECP, len(encs))
	var Cw *BLS381.ECP

	for i := range proof.rk {
		Aw[i] = BLS381.G1mul(encs[i].A, proof.c)            // Aw[i] = (a[i] * c)
		Aw[i].Add(BLS381.G1mul(params.G.Gen1, proof.rk[i])) // Aw[i] = (a[i] * c) + (g1 * rk[i])
	}

	for i := range encs {
		Bw[i] = BLS381.G1mul(encs[i].B, proof.c)    // Bw[i] = (b[i] * c)
		Bw[i].Add(BLS381.G1mul(gamma, proof.rk[i])) // Bw[i] = (b[i] * c) + (gamma * rk[i])
		Bw[i].Add(BLS381.G1mul(h, proof.rm[i]))     // Bw[i] = (b[i] * c) + (gamma * rk[i]) + (h * rm[i])
	}

	Cw = BLS381.G1mul(cm, proof.c)
	Cw.Add(BLS381.G1mul(params.G.Gen1, proof.rr))
	for i := range proof.rm {
		Cw.Add(BLS381.G1mul(params.hs[i], proof.rm[i]))
	}

	// todo: need to wait until amcl people expose BIG comparison method
	// return BLS381.Comp(proof.c, constructChallenge(G.Gen1, G.Gen2, [][]*BLS381.ECP{{cm, h, Cw}, params.hs, Aw, Bw})) == 0
	return false // to make it compile
}

// todo verifier proofs
