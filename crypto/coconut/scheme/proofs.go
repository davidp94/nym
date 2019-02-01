// proofs.go - Non-interactive Zero-Knowledge Proofs Implementation
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

	"0xacab.org/jstuczyn/CoconutGo/constants"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

var (
	// ErrConstructSignerCiphertexts indicates that invalid ciphertexts were provided for construction of
	// proofs for corectness of ciphertexts and cm.
	ErrConstructSignerCiphertexts = errors.New("Invalid ciphertexts provided")

	// ErrConstructSignerAttrs indicates that invalid attributes (either attributes to sign or params generated at setup)
	// were provided for construction of proofs for corectness of ciphertexts and cm.
	ErrConstructSignerAttrs = errors.New("More than specified number of attributes provided")
)

// ConstructChallenge construct a BIG num challenge by hashing a number of Eliptic Curve points
// It's based on the original Python implementation:
// https://github.com/asonnino/coconut/blob/master/coconut/proofs.py#L9.
func ConstructChallenge(elems []utils.Printable) (*Curve.BIG, error) {
	csa := make([]string, len(elems))
	for i := range elems {
		csa[i] = utils.ToCoconutString(elems[i])
	}
	cs := strings.Join(csa, ",")
	return utils.HashStringToBig(amcl.SHA256, cs)
}

// CreateWitnessResponses creates responses for the witnesses for the proofs of knowledge, where
// p is the curve order
// ws are the witnesses
// c is the challenge
// xs are the secrets
func CreateWitnessResponses(p *Curve.BIG, ws []*Curve.BIG, c *Curve.BIG, xs []*Curve.BIG) []*Curve.BIG {
	rs := make([]*Curve.BIG, len(ws))
	for i := range ws {
		rs[i] = ws[i].Minus(Curve.Modmul(c, xs[i], p))
		rs[i] = rs[i].Plus(p)
		rs[i].Mod(p) // rs[i] = (ws[i] - c * xs[i]) % p
	}

	return rs
}

// ConstructSignerProof creates a non-interactive zero-knowledge proof to prove corectness of ciphertexts and cm.
// It's based on the original Python implementation:
// https://github.com/asonnino/coconut/blob/master/coconut/proofs.py#L16
// nolint: interfacer, lll, gocyclo
func ConstructSignerProof(params *Params, gamma *Curve.ECP, encs []*elgamal.Encryption, cm *Curve.ECP, k []*Curve.BIG, r *Curve.BIG, pubM []*Curve.BIG, privM []*Curve.BIG) (*SignerProof, error) {
	p, g1, g2, hs := params.p, params.g1, params.g2, params.hs

	attributes := append(privM, pubM...)
	// if there are no encryptions it means there are no private attributes and hence blind signature should not be used
	if len(encs) <= 0 {
		return nil, ErrConstructSignerCiphertexts
	}
	if len(encs) != len(k) || len(encs) != len(privM) {
		return nil, ErrConstructSignerCiphertexts
	}
	if len(attributes) > len(hs) {
		return nil, ErrConstructSignerAttrs
	}

	// witnesses creation
	wr := GetRandomNums(params, 1)[0]
	wk := GetRandomNums(params, len(k))
	wm := GetRandomNums(params, len(attributes))

	b := make([]byte, constants.ECPLen)
	cm.ToBytes(b, true)

	h, err := utils.HashBytesToG1(amcl.SHA512, b)
	if err != nil {
		return nil, err
	}

	// witnesses commitments
	Aw := make([]*Curve.ECP, len(wk))
	Bw := make([]*Curve.ECP, len(privM))
	var Cw *Curve.ECP

	for i := range wk {
		Aw[i] = Curve.G1mul(g1, wk[i]) // Aw[i] = (wk[i] * g1)
	}
	for i := range privM {
		Bw[i] = Curve.G1mul(h, wm[i])        // Bw[i] = (wm[i] * h)
		Bw[i].Add(Curve.G1mul(gamma, wk[i])) // Bw[i] = (wm[i] * h) + (wk[i] * gamma)
	}

	Cw = Curve.G1mul(g1, wr) // Cw = (wr * g1)
	for i := range attributes {
		Cw.Add(Curve.G1mul(hs[i], wm[i])) // Cw = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
	}

	tmpSlice := []utils.Printable{g1, g2, cm, h, Cw}
	ca := utils.CombinePrintables(
		tmpSlice,
		utils.ECPSliceToPrintable(hs),
		utils.ECPSliceToPrintable(Aw),
		utils.ECPSliceToPrintable(Bw),
	)

	c, err := ConstructChallenge(ca)
	if err != nil {
		return nil, fmt.Errorf("Failed to construct challenge: %v", err)
	}

	// responses
	rr := CreateWitnessResponses(p, []*Curve.BIG{wr}, c, []*Curve.BIG{r})[0] // rr = (wr - c * r) % o
	rk := CreateWitnessResponses(p, wk, c, k)                                // rk[i] = (wk[i] - c * k[i]) % o
	rm := CreateWitnessResponses(p, wm, c, attributes)                       // rm[i] = (wm[i] - c * attributes[i]) % o

	return &SignerProof{
		c:  c,
		rr: rr,
		rk: rk,
		rm: rm,
	}, nil
}

// VerifySignerProof verifies non-interactive zero-knowledge proofs in order to check corectness of ciphertexts and cm.
// It's based on the original Python implementation:
// https://github.com/asonnino/coconut/blob/master/coconut/proofs.py#L41
// nolint: lll
func VerifySignerProof(params *Params, gamma *Curve.ECP, signMats *Lambda) bool {
	g1, g2, hs := params.g1, params.g2, params.hs
	cm, encs, proof := signMats.cm, signMats.enc, signMats.proof

	if len(encs) != len(proof.rk) {
		return false
	}

	b := make([]byte, constants.ECPLen)
	cm.ToBytes(b, true)

	h, err := utils.HashBytesToG1(amcl.SHA512, b)
	if err != nil {
		panic(err)
	}

	Aw := make([]*Curve.ECP, len(proof.rk))
	Bw := make([]*Curve.ECP, len(encs))
	var Cw *Curve.ECP

	for i := range proof.rk {
		Aw[i] = Curve.G1mul(encs[i].C1(), proof.c) // Aw[i] = (c * c1[i])
		Aw[i].Add(Curve.G1mul(g1, proof.rk[i]))    // Aw[i] = (c * c1[i]) + (rk[i] * g1)
	}

	for i := range encs {
		Bw[i] = Curve.G1mul(encs[i].C2(), proof.c) // Bw[i] = (c * c2[i])
		Bw[i].Add(Curve.G1mul(gamma, proof.rk[i])) // Bw[i] = (c * c2[i]) + (rk[i] * gamma)
		Bw[i].Add(Curve.G1mul(h, proof.rm[i]))     // Bw[i] = (c * c2[i]) + (rk[i] * gamma) + (rm[i] * h)
	}

	Cw = Curve.G1mul(cm, proof.c)     // Cw = (cm * c)
	Cw.Add(Curve.G1mul(g1, proof.rr)) // Cw = (cm * c) + (rr * g1)
	for i := range proof.rm {
		Cw.Add(Curve.G1mul(hs[i], proof.rm[i])) // Cw = (cm * c) + (rr * g1) + (rm[0] * hs[0]) + ... + (rm[i] * hs[i])
	}

	tmpSlice := []utils.Printable{g1, g2, cm, h, Cw}
	ca := utils.CombinePrintables(
		tmpSlice,
		utils.ECPSliceToPrintable(hs),
		utils.ECPSliceToPrintable(Aw),
		utils.ECPSliceToPrintable(Bw),
	)

	c, err := ConstructChallenge(ca)
	if err != nil {
		return false
	}

	return Curve.Comp(proof.c, c) == 0
}

// ConstructVerifierProof creates a non-interactive zero-knowledge proof in order to prove corectness of kappa and nu.
// It's based on the original Python implementation:
// https://github.com/asonnino/coconut/blob/master/coconut/proofs.py#L57
// nolint: lll
func ConstructVerifierProof(params *Params, vk *VerificationKey, sig *Signature, privM []*Curve.BIG, t *Curve.BIG) (*VerifierProof, error) {
	p, g1, g2, hs := params.p, params.g1, params.g2, params.hs

	// witnesses creation
	wm := GetRandomNums(params, len(privM))
	wt := GetRandomNums(params, 1)[0]

	// witnesses commitments
	Aw := Curve.G2mul(g2, wt) // Aw = (wt * g2)
	Aw.Add(vk.alpha)          // Aw = (wt * g2) + alpha
	for i := range privM {
		Aw.Add(Curve.G2mul(vk.beta[i], wm[i])) // Aw = (wt * g2) + alpha + (wm[0] * beta[0]) + ... + (wm[i] * beta[i])
	}
	Bw := Curve.G1mul(sig.sig1, wt) // Bw = wt * h

	tmpSlice := []utils.Printable{g1, g2, vk.alpha, Aw, Bw}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.beta))
	c, err := ConstructChallenge(ca)
	if err != nil {
		return nil, fmt.Errorf("Failed to construct challenge: %v", err)
	}

	// responses
	rm := CreateWitnessResponses(p, wm, c, privM)                            // rm[i] = (wm[i] - c * privM[i]) % o
	rt := CreateWitnessResponses(p, []*Curve.BIG{wt}, c, []*Curve.BIG{t})[0] // rt = (wt - c * t) % o

	return &VerifierProof{
		c:  c,
		rm: rm,
		rt: rt,
	}, nil
}

// VerifyVerifierProof verifies non-interactive zero-knowledge proofs in order to check corectness of kappa and nu.
// It's based on the original Python implementation:
// https://github.com/asonnino/coconut/blob/master/coconut/proofs.py#L75
func VerifyVerifierProof(params *Params, vk *VerificationKey, sig *Signature, theta *Theta) bool {
	p, g1, g2, hs := params.p, params.g1, params.g2, params.hs

	Aw := Curve.G2mul(theta.kappa, theta.proof.c) // Aw = (c * kappa)
	Aw.Add(Curve.G2mul(vk.g2, theta.proof.rt))    // Aw = (c * kappa) + (rt * g2)

	// Aw = (c * kappa) + (rt * g2) + (alpha)
	Aw.Add(vk.alpha)
	// Aw = (c * kappa) + (rt * g2) + (alpha - alpha * c) = (c * kappa) + (rt * g2) + ((1 - c) * alpha)
	Aw.Add(Curve.G2mul(vk.alpha, Curve.Modneg(theta.proof.c, p)))

	for i := range theta.proof.rm {
		// Aw = (c * kappa) + (rt * g2) + ((1 - c) * alpha) + (rm[0] * beta[0]) + ... + (rm[i] * beta[i])
		Aw.Add(Curve.G2mul(vk.beta[i], theta.proof.rm[i]))
	}

	Bw := Curve.G1mul(theta.nu, theta.proof.c)    // Bw = (c * nu)
	Bw.Add(Curve.G1mul(sig.sig1, theta.proof.rt)) // Bw = (c * nu) + (rt * h)

	tmpSlice := []utils.Printable{g1, g2, vk.alpha, Aw, Bw}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.beta))
	c, err := ConstructChallenge(ca)
	if err != nil {
		return false
	}

	return Curve.Comp(theta.proof.c, c) == 0
}
