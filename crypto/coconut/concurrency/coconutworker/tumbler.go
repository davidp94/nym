// tumbler.go - Tumbler-related coconutworker functionalities
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

// Package coconutworker provides the functionalities required to use the Coconut scheme concurrently.
package coconutworker

import (
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// ConstructTumblerProof constructs a zero knowledge proof required to
// implement Coconut's coin tumbler (https://arxiv.org/pdf/1802.07344.pdf).
// It proves knowledge of all private attributes in the credential and binds the proof to the address.
// Note that the first privM parameter HAS TO be coin's sequence number since the zeta is later revealed.
// loosely based on: https://github.com/asonnino/coconut-chainspace/blob/master/contracts/tumbler_proofs.py
// TODO: NEED SOMEBODY TO VERIFY CORECTNESS OF IMPLEMENTATION
func (cw *CoconutWorker) ConstructTumblerProof(
	params *MuxParams,
	vk *coconut.VerificationKey,
	sig *coconut.Signature,
	privM []*Curve.BIG,
	t *Curve.BIG,
	address []byte,
) (*coconut.TumblerProof, error) {
	p, g1, g2, hs := params.P(), params.G1(), params.G2(), params.Hs()

	// witnesses creation
	params.Lock()
	wm := coconut.GetRandomNums(params.Params, len(privM))
	wt := coconut.GetRandomNums(params.Params, 1)[0]
	params.Unlock()

	// we put Cw in the jobqueue before Aw/Bw so that it could be worked on concurrently
	CwCh := make(chan interface{}, 1)
	cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, g1, wm[0])

	// witnesses commitments
	Aw, Bw := cw.constructKappaNuCommitments(vk, sig.Sig1(), wt, wm, privM)

	// wm[0] is the coin's sequence number
	CwRes := <-CwCh
	Cw := CwRes.(*Curve.ECP) // Cw = wm[0] * g1

	bind, err := coconut.CreateBinding(address)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to address: %v", err)
	}

	tmpSlice := []utils.Printable{g1, g2, vk.Alpha(), Aw, Bw, Cw, bind}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.Beta()))
	c, err := coconut.ConstructChallenge(ca)
	if err != nil {
		return nil, fmt.Errorf("failed to construct challenge: %v", err)
	}

	// responses
	rm := coconut.CreateWitnessResponses(p, wm, c, privM)                            // rm[i] = (wm[i] - c * privM[i]) % o
	rt := coconut.CreateWitnessResponses(p, []*Curve.BIG{wt}, c, []*Curve.BIG{t})[0] // rt = (wt - c * t) % o

	zeta := Curve.G1mul(g1, privM[0])

	return coconut.NewTumblerProof(coconut.NewVerifierProof(c, rm, rt), zeta), nil
}

// VerifyTumblerProof verifies non-interactive zero-knowledge proofs in order to check corectness of kappa, nu and zeta.
func (cw *CoconutWorker) VerifyTumblerProof(
	params *MuxParams,
	vk *coconut.VerificationKey,
	sig *coconut.Signature,
	theta *coconut.ThetaTumbler,
	address []byte,
) bool {
	g1, g2, hs := params.G1(), params.G2(), params.Hs()

	CwCh := make(chan interface{}, 2)
	cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, g1, theta.Proof().Rm()[0])
	cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, theta.Zeta(), theta.Proof().C())

	Aw, Bw := cw.reconstructKappaNuCommitments(params, vk, sig, theta.Theta)

	CwRes1 := <-CwCh
	CwRes2 := <-CwCh

	Cw := CwRes1.(*Curve.ECP)   // Cw = (g1 * rm[0]) OR Cw = (Zeta * c)
	Cw.Add(CwRes2.(*Curve.ECP)) // Cw = (g1 * rm[0]) + (Zeta * c)

	bind, err := coconut.CreateBinding(address)
	if err != nil {
		return false
	}

	tmpSlice := []utils.Printable{g1, g2, vk.Alpha(), Aw, Bw, Cw, bind}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.Beta()))
	c, err := coconut.ConstructChallenge(ca)
	if err != nil {
		return false
	}

	return Curve.Comp(theta.Proof().C(), c) == 0
}

// ShowBlindSignatureTumbler builds cryptographic material required for blind verification for the tumbler.
// It returns kappa, nu and zeta - group elements needed to perform verification
// and zero-knowledge proof asserting corectness of the above.
// The proof is bound to the provided address.
func (cw *CoconutWorker) ShowBlindSignatureTumbler(
	params *MuxParams,
	vk *coconut.VerificationKey,
	sig *coconut.Signature,
	privM []*Curve.BIG,
	address []byte,
) (*coconut.ThetaTumbler, error) {

	params.Lock()
	t := coconut.GetRandomNums(params.Params, 1)[0]
	params.Unlock()

	kappa, nu, err := cw.ConstructKappaNu(vk, sig, privM, t)
	if err != nil {
		return nil, err
	}

	tumblerProof, err := cw.ConstructTumblerProof(params, vk, sig, privM, t, address)
	if err != nil {
		return nil, err
	}

	return coconut.NewThetaTumbler(
		coconut.NewTheta(
			kappa,
			nu,
			tumblerProof.BaseProof(),
		),
		tumblerProof.Zeta(),
	), nil
}

// BlindVerifyTumbler verifies the Coconut credential on the private and optional public attributes.
// It also checks the attached proof. It is designed to work for the tumbler system.
func (cw *CoconutWorker) BlindVerifyTumbler(
	params *MuxParams,
	vk *coconut.VerificationKey,
	sig *coconut.Signature,
	theta *coconut.ThetaTumbler,
	pubM []*Curve.BIG,
	address []byte,
) bool {
	privateLen := len(theta.Proof().Rm())
	if len(pubM)+privateLen > len(vk.Beta()) || !cw.VerifyTumblerProof(params, vk, sig, theta, address) {
		return false
	}

	if !sig.Validate() {
		return false
	}

	// we put it here so that we could put one of the pairings to the queue already;
	// the other one depends on resolution of aggr
	t1 := Curve.NewECP()
	t1.Copy(sig.Sig2())
	t1.Add(theta.Nu())

	outChPair := make(chan interface{}, 2)
	cw.jobQueue <- jobpacket.MakePairingPacket(outChPair, t1, vk.G2())

	aggr := Curve.NewECP2() // new point is at infinity
	if len(pubM) > 0 {
		aggrCh := make(chan interface{}, len(pubM))
		for i := 0; i < len(pubM); i++ {
			cw.jobQueue <- jobpacket.MakeG2MulPacket(aggrCh, vk.Beta()[i+privateLen], pubM[i])
		}
		for i := 0; i < len(pubM); i++ {
			aggrRes := <-aggrCh
			aggr.Add(aggrRes.(*Curve.ECP2))
		}
	}

	t2 := Curve.NewECP2()
	t2.Copy(theta.Kappa())
	t2.Add(aggr)

	cw.jobQueue <- jobpacket.MakePairingPacket(outChPair, sig.Sig1(), t2)

	res1 := <-outChPair
	res2 := <-outChPair
	gt1 := res1.(*Curve.FP12)
	gt2 := res2.(*Curve.FP12)

	return !sig.Sig1().Is_infinity() && gt1.Equals(gt2)
}
