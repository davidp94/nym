// tumbler.go - Tumbler-related coconut functionalities
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
	fmt "fmt"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// TumblerProof is a special case of VerifierProof that is bound to some address
// and also encapsulates some zeta (g^s).
type TumblerProof struct {
	baseProof *VerifierProof
	zeta      *Curve.ECP
}

// BaseProof returns the base proof containing (c, rm, rt).
func (tp *TumblerProof) BaseProof() *VerifierProof {
	return tp.baseProof
}

// Zeta returns zeta used in the proof.
func (tp *TumblerProof) Zeta() *Curve.ECP {
	return tp.zeta
}

// Validate checks for nil elements in the proof.
func (tp *TumblerProof) Validate() bool {
	if tp == nil || tp.zeta == nil {
		return false
	}
	return tp.baseProof.Validate()
}

// NewTumblerProof returns instance of TumblerProof from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewTumblerProof(baseProof *VerifierProof, zeta *Curve.ECP) *TumblerProof {
	return &TumblerProof{
		baseProof: baseProof,
		zeta:      zeta,
	}
}

// ThetaTumbler encapsulates data created by ShowBlindSignatureTumbler function.
type ThetaTumbler struct {
	*Theta
	zeta *Curve.ECP
}

// Zeta returns the zeta part of the ThetaTumbler.
func (t *ThetaTumbler) Zeta() *Curve.ECP {
	return t.zeta
}

// Validate checks for nil elements in the mats.
func (t *ThetaTumbler) Validate() bool {
	if t.zeta == nil {
		return false
	}
	return t.Theta.Validate()
}

// NewThetaTumbler returns instance of ThetaTumbler from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewThetaTumbler(theta *Theta, zeta *Curve.ECP) *ThetaTumbler {
	return &ThetaTumbler{
		Theta: theta,
		zeta:  zeta,
	}
}

// ConstructTumblerProof constructs a zero knowledge proof required to
// implement Coconut's coin tumbler (https://arxiv.org/pdf/1802.07344.pdf).
// It proves knowledge of all private attributes in the credential and binds the proof to the address.
// Note that the first privM parameter HAS TO be coin's sequence number since the zeta is later revealed.
// loosely based on: https://github.com/asonnino/coconut-chainspace/blob/master/contracts/tumbler_proofs.py
// TODO: NEED SOMEBODY TO VERIFY CORECTNESS OF IMPLEMENTATION
// nolint: lll
func ConstructTumblerProof(params *Params, vk *VerificationKey, sig *Signature, privM []*Curve.BIG, t *Curve.BIG, address []byte) (*TumblerProof, error) {
	p, g1, g2, hs := params.p, params.g1, params.g2, params.hs

	// witnesses creation
	wm := GetRandomNums(params, len(privM))
	wt := GetRandomNums(params, 1)[0]

	// witnesses commitments
	Aw, Bw := constructKappaNuCommitments(vk, sig.sig1, wt, wm, privM)

	// wm[0] is the coin's sequence number
	Cw := Curve.G1mul(g1, wm[0]) // Cw = wm[0] * g1

	bind, err := CreateBinding(address)
	if err != nil {
		return nil, fmt.Errorf("Failed to bind to address: %v", err)
	}

	tmpSlice := []utils.Printable{g1, g2, vk.alpha, Aw, Bw, Cw, bind}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.beta))
	c, err := ConstructChallenge(ca)
	if err != nil {
		return nil, fmt.Errorf("Failed to construct challenge: %v", err)
	}

	// responses
	rm := CreateWitnessResponses(p, wm, c, privM)                            // rm[i] = (wm[i] - c * privM[i]) % o
	rt := CreateWitnessResponses(p, []*Curve.BIG{wt}, c, []*Curve.BIG{t})[0] // rt = (wt - c * t) % o

	zeta := Curve.G1mul(g1, privM[0])

	return &TumblerProof{
		baseProof: &VerifierProof{
			c:  c,
			rm: rm,
			rt: rt,
		},
		zeta: zeta,
	}, nil
}

// VerifyTumblerProof verifies non-interactive zero-knowledge proofs in order to check corectness of kappa, nu and zeta.
func VerifyTumblerProof(params *Params, vk *VerificationKey, sig *Signature, theta *ThetaTumbler, address []byte) bool {
	g1, g2, hs := params.g1, params.g2, params.hs

	Aw, Bw := reconstructKappaNuCommitments(params, vk, sig, theta.Theta)

	Cw := Curve.G1mul(g1, theta.proof.rm[0])
	Cw.Add(Curve.G1mul(theta.zeta, theta.proof.c))

	bind, err := CreateBinding(address)
	if err != nil {
		return false
	}

	tmpSlice := []utils.Printable{g1, g2, vk.alpha, Aw, Bw, Cw, bind}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.beta))
	c, err := ConstructChallenge(ca)
	if err != nil {
		return false
	}

	return Curve.Comp(theta.proof.c, c) == 0
}

// ShowBlindSignatureTumbler builds cryptographic material required for blind verification for the tumbler.
// It returns kappa, nu and zeta - group elements needed to perform verification
// and zero-knowledge proof asserting corectness of the above.
// The proof is bound to the provided address.
func ShowBlindSignatureTumbler(params *Params, vk *VerificationKey, sig *Signature, privM []*Curve.BIG, address []byte) (*ThetaTumbler, error) {
	p, rng := params.p, params.G.Rng()
	t := Curve.Randomnum(p, rng)

	kappa, nu, err := ConstructKappaNu(vk, sig, privM, t)
	if err != nil {
		return nil, err
	}

	tumblerProof, err := ConstructTumblerProof(params, vk, sig, privM, t, address)
	if err != nil {
		return nil, err
	}

	return &ThetaTumbler{
		Theta: &Theta{
			kappa: kappa,
			nu:    nu,
			proof: tumblerProof.baseProof,
		},
		zeta: tumblerProof.zeta,
	}, nil
}

// BlindVerifyTumbler verifies the Coconut credential on the private and optional public attributes.
// It also checks the attached proof. It is designed to work for the tumbler system.
// nolint: lll
func BlindVerifyTumbler(params *Params, vk *VerificationKey, sig *Signature, theta *ThetaTumbler, pubM []*Curve.BIG, address []byte) bool {
	G := params.G

	privateLen := len(theta.proof.rm)
	if len(pubM)+privateLen > len(vk.beta) || !VerifyTumblerProof(params, vk, sig, theta, address) {
		return false
	}

	if sig == nil || sig.Sig1() == nil || sig.Sig2() == nil {
		return false
	}

	aggr := Curve.NewECP2() // new point is at infinity
	if len(pubM) > 0 {
		for i := 0; i < len(pubM); i++ {
			aggr.Add(Curve.G2mul(vk.beta[i+privateLen], pubM[i]))
		}
	}

	t1 := Curve.NewECP2()
	t1.Copy(theta.kappa)
	t1.Add(aggr)

	t2 := Curve.NewECP()
	t2.Copy(sig.sig2)
	t2.Add(theta.nu)

	Gt1 := G.Pair(sig.sig1, t1)
	Gt2 := G.Pair(t2, vk.g2)

	return !sig.sig1.Is_infinity() && Gt1.Equals(Gt2)
}
