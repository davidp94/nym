// scheme.go - Coconut signature scheme
// Copyright (C) 2018  Jedrzej Stuczynski.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package coconut provides the functionalities required by the Coconut Scheme.
package coconut

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	Curve "github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// todo: allow for q being arbitrary larger than number of signed parameters
// todo: remove the way functions are currently executed concurrently
// todo: parallelization with worker pool
// todo: modify data in Params to be consistent with the original paper
// todo: make errors private
// todo: rename and restructure PolynomialPoints struct + all its uses
// todo: comments with maths computation
// todo: comments with python sources

// SecretKey represents secret key of a Coconut signing authority.
type SecretKey struct {
	x *Curve.BIG
	y []*Curve.BIG
}

// VerificationKey represents verification key of a Coconut signing authority.
type VerificationKey struct {
	g2    *Curve.ECP2
	alpha *Curve.ECP2
	beta  []*Curve.ECP2
}

// Signature represents signature/credential issued by a Coconut signing authority.
// sig1 = h,
// sig2 = h * (x + (m[0] * y[0]) + ... + (m[i] * y[i])).
type Signature struct {
	sig1 *Curve.ECP
	sig2 *Curve.ECP
}

// BlindedSignature represents blinded version of a normal Coconut signature
type BlindedSignature struct {
	sig1      *Curve.ECP
	sig2Tilda *elgamal.ElGamalEncryption
}

// Params represent public system-wide parameters.
type Params struct {
	G  *bpgroup.BpGroup
	hs []*Curve.ECP
}

// BlindSignMats encapsulates data created by PrepareBlindSign function.
type BlindSignMats struct {
	cm    *Curve.ECP
	enc   []*elgamal.ElGamalEncryption
	proof *SignerProof
}

// BlindShowMats encapsulates data created by ShowBlindSignature function.
type BlindShowMats struct {
	kappa *Curve.ECP2
	nu    *Curve.ECP
	proof *VerifierProof
}

// PolynomialPoints (tmp) represents x values of points on polynomial of degree t - 1
// generated during TTPKeygen.
type PolynomialPoints struct {
	xs []*Curve.BIG
}

var (
	// ErrSetupParams indicates incorrect parameters provided for Setup.
	ErrSetupParams = errors.New("Can't generate params for less than 1 attribute")

	// ErrSignParams indicates inconsistent parameters provided for Sign.
	ErrSignParams = errors.New("Invalid attributes/secret key provided")

	// ErrKeygenParams indicates incorrect parameters provided for Keygen.
	ErrKeygenParams = errors.New("Can't generate keys for less than 1 attribute")

	// ErrTTPKeygenParams indicates incorrect parameters provided for TTPKeygen.
	ErrTTPKeygenParams = errors.New("Invalid set of parameters provided to keygen")

	// ErrPrepareBlindSignParams indicates that number of attributes to sign is larger than q specified in Setup.
	ErrPrepareBlindSignParams = errors.New("Too many attributes to sign")

	// ErrPrepareBlindSignPrivate indicates lack of private attributes to blindly sign.
	ErrPrepareBlindSignPrivate = errors.New("No private attributes to sign")

	// ErrBlindSignParams indicates that number of attributes to sign is larger than q specified in Setup.
	ErrBlindSignParams = errors.New("Too many attributes to sign")

	// ErrBlindSignProof indicates that proof of corectness of ciphertext and cm was invalid
	ErrBlindSignProof = errors.New("Failed to verify the proof")

	// ErrShowBlindAttr indicates that either there were no private attributes provided
	// or their number was larger than the verification key supports
	ErrShowBlindAttr = errors.New("Invalid attributes provided")
)

// Setup generates the public parameters required by the Coconut scheme.
// q indicates the maximum number of attributes that can be embed in the credentials.
func Setup(q int) (*Params, error) {
	if q < 1 {
		return nil, ErrSetupParams
	}
	var wg sync.WaitGroup
	wg.Add(q)
	hs := make([]*Curve.ECP, q)
	for i := 0; i < q; i++ {
		go func(i int) {
			hi, err := utils.HashStringToG1(amcl.SHA256, fmt.Sprintf("h%d", i))
			if err != nil {
				panic(err)
			}
			hs[i] = hi
			wg.Done()
		}(i)
	}
	wg.Wait()
	G := bpgroup.New()
	return &Params{G, hs}, nil
}

// Keygen generates a single Coconut keypair ((x, y1, y2...), (g2, g2^x, g2^y1, ...)).
// It is not suitable for threshold credentials as all generated keys are independent of each other.
func Keygen(params *Params) (*SecretKey, *VerificationKey, error) {
	q := len(params.hs)
	if q < 1 {
		return nil, nil, ErrKeygenParams
	}
	G := params.G

	x := Curve.Randomnum(G.Ord, G.Rng)
	y := make([]*Curve.BIG, q)
	sk := &SecretKey{x: x, y: y}

	for i := 0; i < q; i++ {
		y[i] = Curve.Randomnum(G.Ord, G.Rng)
	}

	alpha := Curve.G2mul(G.Gen2, x)
	beta := make([]*Curve.ECP2, q)
	vk := &VerificationKey{g2: G.Gen2, alpha: alpha, beta: beta}

	var wg sync.WaitGroup
	wg.Add(q)

	for i := 0; i < q; i++ {
		go func(i int) {
			beta[i] = Curve.G2mul(G.Gen2, y[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	return sk, vk, nil
}

// TTPKeygen generates a set of n Coconut keypairs [((x, y1, y2...), (g2, g2^x, g2^y1, ...)), ...],
// such that they support threshold aggregation of t parties.
// It is expected that this procedure is executed by a Trusted Third Party.
func TTPKeygen(params *Params, t int, n int) ([]*SecretKey, []*VerificationKey, error) {
	q := len(params.hs)
	G := params.G
	if n < t || t <= 0 || q <= 0 {
		return nil, nil, ErrTTPKeygenParams
	}

	// polynomials generation
	v := make([]*Curve.BIG, t)
	for i := range v {
		v[i] = Curve.Randomnum(G.Ord, G.Rng)
	}

	w := make([][]*Curve.BIG, q)
	for i := range w {
		w[i] = make([]*Curve.BIG, t)
		for j := range w[i] {
			w[i][j] = Curve.Randomnum(G.Ord, G.Rng)
		}
	}

	var wg sync.WaitGroup
	wg.Add(n)
	// secret keys
	sks := make([]*SecretKey, n)
	// we can use any is now, rather than 1,2...,n; might be useful if we have some authorities ids?
	for i := 1; i < n+1; i++ {
		go func(i int) {
			iBIG := Curve.NewBIGint(i)
			x := utils.PolyEval(v, iBIG, G.Ord)
			ys := make([]*Curve.BIG, q)
			for j, wj := range w {
				ys[j] = utils.PolyEval(wj, iBIG, G.Ord)
			}
			sks[i-1] = &SecretKey{x: x, y: ys}
			wg.Done()
		}(i)
	}
	wg.Wait()
	// no point in overdoing it by assigning new goroutine to each G2mul
	// (it's unlikely we'd have enough CPU cores to make use of that)
	wg.Add(n)

	// verification keys
	vks := make([]*VerificationKey, n)
	for i := range sks {
		go func(i int) {
			alpha := Curve.G2mul(G.Gen2, sks[i].x)
			beta := make([]*Curve.ECP2, q)
			for j, yj := range sks[i].y {
				beta[j] = Curve.G2mul(G.Gen2, yj)
			}
			vks[i] = &VerificationKey{g2: G.Gen2, alpha: alpha, beta: beta}
			wg.Done()
		}(i)
	}
	wg.Wait()
	return sks, vks, nil
}

// getBaseFromAttributes generates the base h from public attributes.
// It is only used for Sign function that works exlusively on public attributes
func getBaseFromAttributes(pubM []*Curve.BIG) *Curve.ECP {
	s := make([]string, len(pubM))
	for i := range pubM {
		s[i] = pubM[i].ToString()
	}
	h, err := utils.HashStringToG1(amcl.SHA256, strings.Join(s, ","))
	if err != nil {
		panic(err)
	}
	return h
}

// Sign creates a Coconut credential under a given secret key on a set of public attributes only.
func Sign(params *Params, sk *SecretKey, pubM []*Curve.BIG) (*Signature, error) {
	if len(pubM) != len(sk.y) {
		return nil, ErrSignParams
	}
	G := params.G
	h := getBaseFromAttributes(pubM)

	K := Curve.NewBIGcopy(sk.x) // K = x
	for i := 0; i < len(pubM); i++ {
		tmp := Curve.Modmul(sk.y[i], pubM[i], G.Ord) // (ai * yi)
		K = K.Plus(tmp)                              // K = x + (a0 * y0) + ...
	}
	sig := Curve.G1mul(h, K) // sig = h^(x + (a0 * y0) + ... )

	return &Signature{h, sig}, nil
}

// PrepareBlindSign builds cryptographic material for blind sign.
// It returns commitment to the private and public attributes,
// encryptions of the private attributes
// and zero-knowledge proof asserting corectness of the above.
func PrepareBlindSign(params *Params, gamma *Curve.ECP, pubM []*Curve.BIG, privM []*Curve.BIG) (*BlindSignMats, error) {
	G := params.G
	if len(privM) <= 0 {
		return nil, ErrPrepareBlindSignPrivate
	}
	attributes := append(privM, pubM...)
	if len(attributes) > len(params.hs) {
		return nil, ErrPrepareBlindSignParams
	}

	r := Curve.Randomnum(G.Ord, G.Rng)
	cm := Curve.G1mul(params.G.Gen1, r)

	cmElems := make([]*Curve.ECP, len(attributes))
	var wg sync.WaitGroup
	wg.Add(len(attributes))
	for i := range attributes {
		go func(i int) {
			cmElems[i] = Curve.G1mul(params.hs[i], attributes[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	for _, elem := range cmElems {
		cm.Add(elem)
	}

	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
	if err != nil {
		return nil, err
	}

	encs := make([]*elgamal.ElGamalEncryption, len(privM))
	ks := make([]*Curve.BIG, len(privM))
	// can't easily encrypt in parallel since random number generator object is shared between encryptions
	for i := range privM {
		c, k := elgamal.Encrypt(G, gamma, privM[i], h)
		encs[i] = c
		ks[i] = k
	}

	signerProof, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, pubM, privM)
	if err != nil {
		return nil, err
	}
	return &BlindSignMats{
		cm:    cm,
		enc:   encs,
		proof: signerProof,
	}, nil
}

// BlindSign creates a blinded Coconut credential on the attributes provided to PrepareBlindSign.
func BlindSign(params *Params, sk *SecretKey, blindSignMats *BlindSignMats, gamma *Curve.ECP, pubM []*Curve.BIG) (*BlindedSignature, error) {
	if len(blindSignMats.enc)+len(pubM) > len(params.hs) {
		return nil, ErrBlindSignParams
	}
	if !VerifySignerProof(params, gamma, blindSignMats.enc, blindSignMats.cm, blindSignMats.proof) {
		return nil, ErrBlindSignProof
	}
	h, err := utils.HashStringToG1(amcl.SHA256, blindSignMats.cm.ToString())
	if err != nil {
		return nil, err
	}

	t1 := make([]*Curve.ECP, len(pubM))
	var wg sync.WaitGroup
	wg.Add(len(pubM))
	for i := range pubM {
		go func(i int) {
			t1[i] = Curve.G1mul(h, pubM[i])
			wg.Done()
		}(i)
	}
	wg.Wait()

	t2 := Curve.G1mul(blindSignMats.enc[0].A, sk.y[0])
	wg.Add(len(blindSignMats.enc) - 1)
	t2Elems := make([]*Curve.ECP, len(blindSignMats.enc)-1)
	for i := 1; i < len(blindSignMats.enc); i++ {
		go func(i int) {
			t2Elems[i-1] = Curve.G1mul(blindSignMats.enc[i].A, sk.y[i])
			wg.Done()
		}(i)
	}
	wg.Wait()

	for _, elem := range t2Elems {
		t2.Add(elem)
	}

	t3 := Curve.G1mul(h, sk.x)
	tmpSlice := make([]*Curve.ECP, len(blindSignMats.enc))
	for i := range blindSignMats.enc {
		tmpSlice[i] = blindSignMats.enc[i].B
	}
	tmpSlice = append(tmpSlice, t1...)

	// tmpslice: all B + t1
	t3Elems := make([]*Curve.ECP, len(sk.y))
	wg.Add(len(sk.y))
	for i := range sk.y {
		go func(i int) {
			t3Elems[i] = Curve.G1mul(tmpSlice[i], sk.y[i])
			wg.Done()
		}(i)
	}
	wg.Wait()

	for _, elem := range t3Elems {
		t3.Add(elem)
	}

	return &BlindedSignature{
		sig1: h,
		sig2Tilda: &elgamal.ElGamalEncryption{
			A: t2,
			B: t3,
		},
	}, nil
}

// Unblind unblinds the blinded Coconut credential.
func Unblind(params *Params, blindedSignature *BlindedSignature, d *Curve.BIG) *Signature {
	sig2 := elgamal.Decrypt(params.G, d, blindedSignature.sig2Tilda)
	return &Signature{
		sig1: blindedSignature.sig1,
		sig2: sig2,
	}
}

// Verify verifies the Coconut credential that has been either issued exlusiviely on public attributes
// or all private attributes have been publicly revealed
func Verify(params *Params, vk *VerificationKey, pubM []*Curve.BIG, sig *Signature) bool {
	if len(pubM) != len(vk.beta) {
		return false
	}
	G := params.G

	K := Curve.NewECP2()
	K.Copy(vk.alpha) // K = X
	tmp := make([]*Curve.ECP2, len(pubM))

	var wg sync.WaitGroup
	wg.Add(len(pubM))
	for i := 0; i < len(pubM); i++ {
		go func(i int) {
			tmp[i] = Curve.G2mul(vk.beta[i], pubM[i]) // (ai * Yi)
			wg.Done()
		}(i)
	}
	wg.Wait()
	for i := 0; i < len(pubM); i++ {
		K.Add(tmp[i]) // K = X + (a1 * Y1) + ...
	}

	wg.Add(2)
	var Gt1 *Curve.FP12
	var Gt2 *Curve.FP12

	go func() {
		Gt1 = G.Pair(sig.sig1, K)
		wg.Done()
	}()
	go func() {
		Gt2 = G.Pair(sig.sig2, vk.g2)
		wg.Done()
	}()
	wg.Wait()

	return !sig.sig1.Is_infinity() && Gt1.Equals(Gt2)
}

// ShowBlindSignature builds cryptographic material required for blind verification.
// It returns kappa and nu - group elements needed to perform verification
// and zero-knowledge proof asserting corectness of the above.
func ShowBlindSignature(params *Params, vk *VerificationKey, sig *Signature, privM []*Curve.BIG) (*BlindShowMats, error) {
	G := params.G
	if len(privM) <= 0 || len(privM) > len(vk.beta) {
		return nil, ErrShowBlindAttr
	}

	t := Curve.Randomnum(G.Ord, G.Rng)
	kappa := Curve.G2mul(vk.g2, t)
	kappa.Add(vk.alpha)
	for i := range privM {
		kappa.Add(Curve.G2mul(vk.beta[i], privM[i]))
	}
	nu := Curve.G1mul(sig.sig1, t)

	verifierProof := ConstructVerifierProof(params, vk, sig, privM, t)

	return &BlindShowMats{
		kappa: kappa,
		nu:    nu,
		proof: verifierProof,
	}, nil
}

// BlindVerify verifies the Coconut credential on the private and optional public attributes.
func BlindVerify(params *Params, vk *VerificationKey, sig *Signature, showMats *BlindShowMats, pubM []*Curve.BIG) bool {
	privateLen := len(showMats.proof.rm)
	if len(pubM)+privateLen > len(vk.beta) || !VerifyVerifierProof(params, vk, sig, showMats) {
		return false
	}

	var aggr *Curve.ECP2
	if len(pubM) <= 0 {
		aggr = Curve.NewECP2() // new point is at infinity
	} else {
		aggr = Curve.G2mul(vk.beta[privateLen], pubM[0]) // guaranteed to have at least 1 element
		for i := 1; i < len(pubM); i++ {
			aggr.Add(Curve.G2mul(vk.beta[i+privateLen], pubM[i]))
		}
	}
	t1 := Curve.NewECP2()
	t1.Copy(showMats.kappa)
	t1.Add(aggr)

	t2 := Curve.NewECP()
	t2.Copy(sig.sig2)
	t2.Add(showMats.nu)

	Gt1 := params.G.Pair(sig.sig1, t1)
	Gt2 := params.G.Pair(t2, vk.g2)

	return !sig.sig1.Is_infinity() && Gt1.Equals(Gt2)
}

// Randomize randomizes the Coconut credential such that it becomes indistinguishable
// from a fresh credential on different attributes
func Randomize(params *Params, sig *Signature) *Signature {
	G := params.G
	var wg sync.WaitGroup
	var rSig Signature
	t := Curve.Randomnum(G.Ord, G.Rng)
	wg.Add(2)
	go func() {
		rSig.sig1 = Curve.G1mul(sig.sig1, t)
		wg.Done()
	}()
	go func() {
		rSig.sig2 = Curve.G1mul(sig.sig2, t)
		wg.Done()
	}()
	wg.Wait()
	return &rSig
}

// AggregateVerificationKeys aggregates verification keys of the signing authorities.
// Optionally it does so in a threshold manner.
func AggregateVerificationKeys(params *Params, vks []*VerificationKey, pp *PolynomialPoints) *VerificationKey {
	var alpha *Curve.ECP2
	beta := make([]*Curve.ECP2, len(vks[0].beta))

	if pp != nil {
		t := len(vks)
		l := make([]*Curve.BIG, t)
		for i := 0; i < t; i++ {
			l[i] = utils.LagrangeBasis(i, params.G.Ord, pp.xs, 0)
		}

		alpha = Curve.G2mul(vks[0].alpha, l[0])
		for i := 1; i < len(vks); i++ {
			alpha.Add(Curve.G2mul(vks[i].alpha, l[i]))
		}

		for i := 0; i < len(vks[0].beta); i++ {
			beta[i] = Curve.G2mul(vks[0].beta[i], l[0])
		}

		for i := 1; i < len(vks); i++ { // we already got values from first set of keys
			for j := 0; j < len(beta); j++ {
				beta[j].Add(Curve.G2mul(vks[i].beta[j], l[i]))
			}
		}

	} else {
		alpha = Curve.NewECP2()
		alpha.Copy(vks[0].alpha)
		for i := 1; i < len(vks); i++ {
			alpha.Add(vks[i].alpha)
		}

		for i := 0; i < len(vks[0].beta); i++ {
			beta[i] = Curve.NewECP2()
			beta[i].Copy(vks[0].beta[i])
		}

		for i := 1; i < len(vks); i++ { // we already copied values from first set of keys
			for j := 0; j < len(beta); j++ {
				beta[j].Add(vks[i].beta[j])
			}
		}
	}

	return &VerificationKey{
		g2:    vks[0].g2,
		alpha: alpha,
		beta:  beta,
	}
}

// AggregateSignatures aggregates Coconut credentials on the same set of attributes
// that were produced by multiple signing authorities.
// Optionally it does so in a threshold manner.
func AggregateSignatures(params *Params, sigs []*Signature, pp *PolynomialPoints) *Signature {
	var sig2 *Curve.ECP
	if pp != nil {
		t := len(sigs)
		l := make([]*Curve.BIG, t)
		for i := 0; i < t; i++ {
			l[i] = utils.LagrangeBasis(i, params.G.Ord, pp.xs, 0)
		}
		sig2 = Curve.G1mul(sigs[0].sig2, l[0])
		for i := 1; i < len(sigs); i++ {
			sig2.Add(Curve.G1mul(sigs[i].sig2, l[i]))
		}
	} else {
		sig2 = Curve.NewECP()
		sig2.Copy(sigs[0].sig2)

		for i := 1; i < len(sigs); i++ {
			sig2.Add(sigs[i].sig2)
		}
	}

	return &Signature{
		sig1: sigs[0].sig1,
		sig2: sig2,
	}
}
