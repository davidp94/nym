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
		return nil, fmt.Errorf("Failed to bind to address: %v", err)
	}

	tmpSlice := []utils.Printable{g1, g2, vk.Alpha(), Aw, Bw, Cw, bind}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.Beta()))
	c, err := coconut.ConstructChallenge(ca)
	if err != nil {
		return nil, fmt.Errorf("Failed to construct challenge: %v", err)
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
