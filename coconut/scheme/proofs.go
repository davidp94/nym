package coconut

//  todo: consider renaming all functions

import (
	"errors"
	"strings"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// todo: get proper names for below
type SignerProof struct {
	c  *BLS381.BIG
	rr *BLS381.BIG
	rk []*BLS381.BIG
	rm []*BLS381.BIG
}

// todo
type VerifierProof struct {
	c  *BLS381.BIG
	rm []*BLS381.BIG
	rt *BLS381.BIG
}

type Printable interface {
	ToString() string
}

var (
	ErrConstructSignerCiphertexts = errors.New("Invalid ciphertexts provided")
	ErrConstructSignerAttrs       = errors.New("More than specified number of attributes provided")
)

func constructChallenge(elems []Printable) *BLS381.BIG {
	csa := make([]string, len(elems))
	for i := range elems {
		csa[i] = elems[i].ToString()
	}
	cs := strings.Join(csa, ",")
	c, err := utils.HashStringToBig(amcl.SHA256, cs)
	if err != nil {
		panic(err)
	}
	return c
}

// todo: as before add concurrency once basic version is functional
func ConstructSignerProof(params *Params, gamma *BLS381.ECP, encs []*elgamal.ElGamalEncryption, cm *BLS381.ECP, k []*BLS381.BIG, r *BLS381.BIG, public_m []*BLS381.BIG, private_m []*BLS381.BIG) (*SignerProof, error) {
	attributes := append(private_m, public_m...)
	G := params.G
	if len(encs) != len(k) || len(encs) != len(private_m) {
		return nil, ErrConstructSignerCiphertexts
	}
	if len(attributes) > len(params.hs) {
		return nil, ErrConstructSignerAttrs
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

	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
	if err != nil {
		return nil, err
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

	ca := make([]Printable, 5+len(params.hs)+len(Aw)+len(Bw)) // 5 are: Gen1, Gen2, cm, h and Cw,
	// todo: find a way to simplify the below? - perhaps a function to copy some slice into given part of target slice
	i := 0
	for _, item := range []Printable{G.Gen1, G.Gen2, cm, h, Cw} {
		ca[i] = item
		i++
	}
	for _, item := range params.hs {
		ca[i] = item
		i++
	}
	for _, item := range Aw {
		ca[i] = item
		i++
	}
	for _, item := range Bw {
		ca[i] = item
		i++
	}

	c := constructChallenge(ca)

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
func VerifySignerProof(params *Params, gamma *BLS381.ECP, encs []*elgamal.ElGamalEncryption, cm *BLS381.ECP, proof *SignerProof) bool {
	if len(encs) != len(proof.rk) {
		return false
	}
	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
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

	ca := make([]Printable, 5+len(params.hs)+len(Aw)+len(Bw)) // 5 are both gens, cm, h and Cw,
	// todo: find a way to simplify the below?
	i := 0
	for _, item := range []Printable{params.G.Gen1, params.G.Gen2, cm, h, Cw} {
		ca[i] = item
		i++
	}
	for _, item := range params.hs {
		ca[i] = item
		i++
	}
	for _, item := range Aw {
		ca[i] = item
		i++
	}
	for _, item := range Bw {
		ca[i] = item
		i++
	}

	return BLS381.Comp(proof.c, constructChallenge(ca)) == 0
}

func ConstructVerifierProof(params *Params, vk *VerificationKey, sig *Signature, private_m []*BLS381.BIG, t *BLS381.BIG) *VerifierProof {
	G := params.G

	// witnesses
	wm := make([]*BLS381.BIG, len(private_m))
	for i := 0; i < len(private_m); i++ {
		wm[i] = BLS381.Randomnum(G.Ord, G.Rng)
	}
	wt := BLS381.Randomnum(G.Ord, G.Rng)

	// witnesses commitments
	Aw := BLS381.G2mul(G.Gen2, wt) // Aw = (wt * g2)
	Aw.Add(vk.alpha)               // Aw = (wt * g2) + alpha
	for i := range private_m {
		Aw.Add(BLS381.G2mul(vk.beta[i], wm[i])) // Aw = (wt * g2) + alpha + (wm[i] * beta[i])
	}
	Bw := BLS381.G1mul(sig.sig1, wt)

	ca := make([]Printable, 5+len(params.hs)+len(vk.beta)) // 5 are both gens, alpha, Aw and Bw
	i := 0
	for _, item := range []Printable{params.G.Gen1, params.G.Gen2, vk.alpha, Aw, Bw} {
		ca[i] = item
		i++
	}
	for _, item := range params.hs {
		ca[i] = item
		i++
	}
	for _, item := range vk.beta {
		ca[i] = item
		i++
	}
	// challenge
	c := constructChallenge(ca)

	//responses
	rm := make([]*BLS381.BIG, len(private_m))
	for i := range private_m {
		rm[i] = wm[i].Minus(BLS381.Modmul(c, private_m[i], G.Ord))
		rm[i].Mod(G.Ord)
	}

	rt := wt.Minus(BLS381.Modmul(c, t, G.Ord))
	// todo: add order to each result to ensure positive results?
	rt.Mod(G.Ord)

	return &VerifierProof{
		c:  c,
		rm: rm,
		rt: rt,
	}
}

func VerifyVerifierProof(params *Params, vk *VerificationKey, sig *Signature, showMats *BlindShowMats) bool {
	Aw := BLS381.G2mul(showMats.kappa, showMats.proof.c) // Aw = (c * kappa)
	Aw.Add(BLS381.G2mul(vk.g2, showMats.proof.rt))       // Aw = (c * kappa) + (rt * g2)

	Aw.Add(vk.alpha)                                                              // Aw = (c * kappa) + (rt * g2) + (alpha)
	Aw.Add(BLS381.G2mul(vk.alpha, BLS381.Modneg(showMats.proof.c, params.G.Ord))) // Aw = (c * kappa) + (rt * g2) + (alpha - alpha * c)

	for i := range showMats.proof.rm {
		Aw.Add(BLS381.G2mul(vk.beta[i], showMats.proof.rm[i])) // Aw = (c * kappa) + (rt * g2) + ((1 - c) * alpha) + (rm[i] * beta[i])
	}

	Bw := BLS381.G1mul(showMats.nu, showMats.proof.c) // Bw = (c * nu)
	Bw.Add(BLS381.G1mul(sig.sig1, showMats.proof.rt)) // Bw = (c * nu) + (rt * h)

	ca := make([]Printable, 5+len(params.hs)+len(vk.beta)) // 5 are both gens, alpha, Aw and Bw
	i := 0
	for _, item := range []Printable{params.G.Gen1, params.G.Gen2, vk.alpha, Aw, Bw} {
		ca[i] = item
		i++
	}
	for _, item := range params.hs {
		ca[i] = item
		i++
	}
	for _, item := range vk.beta {
		ca[i] = item
		i++
	}
	return BLS381.Comp(showMats.proof.c, constructChallenge(ca)) == 0
}
