// proofs.go - Worker for the Coconut scheme
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

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// ConstructSignerProof creates a non-interactive zero-knowledge proof to prove corectness of ciphertexts and cm.
// nolint: lll, gocyclo
func (cw *CoconutWorker) ConstructSignerProof(params *MuxParams, gamma *Curve.ECP, encs []*elgamal.Encryption, cm *Curve.ECP, k []*Curve.BIG, r *Curve.BIG, pubM []*Curve.BIG, privM []*Curve.BIG) (*coconut.SignerProof, error) {
	p, g1, g2, hs := params.P(), params.G1(), params.G2(), params.Hs()

	attributes := append(privM, pubM...)
	// if there are no encryptions it means there are no private attributes and hence blind signature should not be used
	if len(encs) <= 0 {
		return nil, coconut.ErrConstructSignerCiphertexts
	}
	if len(encs) != len(k) || len(encs) != len(privM) {
		return nil, coconut.ErrConstructSignerCiphertexts
	}
	if len(attributes) > len(hs) {
		return nil, coconut.ErrConstructSignerAttrs
	}

	// witnesses creation
	params.Lock()
	wr := coconut.GetRandomNums(params.Params, 1)[0]
	wk := coconut.GetRandomNums(params.Params, len(k))
	wm := coconut.GetRandomNums(params.Params, len(attributes))
	params.Unlock()

	b := make([]byte, constants.ECPLen)
	cm.ToBytes(b, true)

	h, err := utils.HashBytesToG1(amcl.SHA512, b)
	if err != nil {
		return nil, err
	}

	// witnesses commitments
	Aw := make([]*Curve.ECP, len(wk))
	Bw := make([]*Curve.ECP, len(privM))
	Cw := Curve.NewECP()

	AwChs := make([]chan interface{}, len(wk))
	BwChs := make([]chan interface{}, len(privM))
	CwCh := make(chan interface{}, 1+len(attributes))

	for i := range wk {
		AwChs[i] = make(chan interface{}, 1)
		cw.jobQueue <- jobpacket.MakeG1MulPacket(AwChs[i], g1, wk[i]) // Aw[i] = (wk[i] * g1)
	}

	for i := range wk {
		// buf for 2 - (wm[i] * h) AND (wk[i] * gamma) - order does not matter because they're added together later
		BwChs[i] = make(chan interface{}, 2)
		cw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], h, wm[i])
		cw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], gamma, wk[i])
	}

	cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, g1, wr)
	for i := range attributes {
		cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, hs[i], wm[i])
	}

	for i := range wk {
		AwiRes := <-AwChs[i]
		Aw[i] = AwiRes.(*Curve.ECP)
	}
	for i := range privM {
		BwiRes1 := <-BwChs[i]
		BwiRes2 := <-BwChs[i]
		Bw[i] = BwiRes1.(*Curve.ECP)    // Bw[i] = (wm[i] * h) OR Bw[i] = (wk[i] * gamma)
		Bw[i].Add(BwiRes2.(*Curve.ECP)) // Bw[i] = (wm[i] * h) + (wk[i] * gamma)
	}

	for i := 0; i <= len(attributes); i++ {
		CwElemRes := <-CwCh
		Cw.Add(CwElemRes.(*Curve.ECP)) // Cw = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
	}

	tmpSlice := []utils.Printable{g1, g2, cm, h, Cw}
	ca := utils.CombinePrintables(
		tmpSlice,
		utils.ECPSliceToPrintable(hs),
		utils.ECPSliceToPrintable(Aw),
		utils.ECPSliceToPrintable(Bw),
	)

	c, err := coconut.ConstructChallenge(ca)
	if err != nil {
		return nil, fmt.Errorf("Failed to construct challenge: %v", err)
	}

	// responses
	rr := coconut.CreateWitnessResponses(p, []*Curve.BIG{wr}, c, []*Curve.BIG{r})[0] // rr = (wr - c * r) % o
	rk := coconut.CreateWitnessResponses(p, wk, c, k)                                // rk[i] = (wk[i] - c * k[i]) % o
	rm := coconut.CreateWitnessResponses(p, wm, c, attributes)                       // rm[i] = (wm[i] - c * attributes[i]) % o

	return coconut.NewSignerProof(c, rr, rk, rm), nil
}

// VerifySignerProof verifies non-interactive zero-knowledge proofs in order to check corectness of ciphertexts and cm.
func (cw *CoconutWorker) VerifySignerProof(params *MuxParams, gamma *Curve.ECP, signMats *coconut.Lambda) bool {
	g1, g2, hs := params.G1(), params.G2(), params.Hs()
	cm, encs, proof := signMats.Cm(), signMats.Enc(), signMats.Proof()

	if len(encs) != len(proof.Rk()) {
		return false
	}

	b := make([]byte, constants.ECPLen)
	cm.ToBytes(b, true)

	h, err := utils.HashBytesToG1(amcl.SHA512, b)
	if err != nil {
		panic(err)
	}

	Aw := make([]*Curve.ECP, len(proof.Rk()))
	Bw := make([]*Curve.ECP, len(encs))
	Cw := Curve.NewECP()

	AwChs := make([]chan interface{}, len(proof.Rk()))
	BwChs := make([]chan interface{}, len(encs))
	CwCh := make(chan interface{}, 2+len(proof.Rm()))

	for i := range proof.Rk() {
		// buf for 2 - (c * c1[i]) AND (rk[i] * g1)  - order does not matter because they're added together later
		AwChs[i] = make(chan interface{}, 2)
		cw.jobQueue <- jobpacket.MakeG1MulPacket(AwChs[i], encs[i].C1(), proof.C())
		cw.jobQueue <- jobpacket.MakeG1MulPacket(AwChs[i], g1, proof.Rk()[i])
	}

	for i := range encs {
		BwChs[i] = make(chan interface{}, 3) // buf for 3 - (c * c2[i]) AND (rk[i] * gamma) AND (rm[i] * h)
		cw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], encs[i].C2(), proof.C())
		cw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], gamma, proof.Rk()[i])
		cw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], h, proof.Rm()[i])
	}

	cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, cm, proof.C())
	cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, g1, proof.Rr())
	for i := range proof.Rm() {
		cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, hs[i], proof.Rm()[i])
	}

	for i := range proof.Rk() {
		AwiRes1 := <-AwChs[i]
		AwiRes2 := <-AwChs[i]
		Aw[i] = AwiRes1.(*Curve.ECP)
		Aw[i].Add(AwiRes2.(*Curve.ECP)) // Aw[i] = (c * c1[i]) + (rk[i] * g1)
	}

	for i := range encs {
		BwiRes1 := <-BwChs[i]
		BwiRes2 := <-BwChs[i]
		BwiRes3 := <-BwChs[i]
		Bw[i] = BwiRes1.(*Curve.ECP)
		Bw[i].Add(BwiRes2.(*Curve.ECP))
		Bw[i].Add(BwiRes3.(*Curve.ECP)) // Bw[i] = (c * c2[i]) + (rk[i] * gamma) + (rm[i] * h)
	}

	for i := 0; i < len(proof.Rm())+2; i++ {
		CwElemRes := <-CwCh
		Cw.Add(CwElemRes.(*Curve.ECP)) // Cw = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
	}

	tmpSlice := []utils.Printable{g1, g2, cm, h, Cw}
	ca := utils.CombinePrintables(
		tmpSlice,
		utils.ECPSliceToPrintable(hs),
		utils.ECPSliceToPrintable(Aw),
		utils.ECPSliceToPrintable(Bw),
	)

	c, err := coconut.ConstructChallenge(ca)
	if err != nil {
		return false
	}

	return Curve.Comp(proof.C(), c) == 0
}

func (cw *CoconutWorker) constructKappaNuCommitments(vk *coconut.VerificationKey, h *Curve.ECP, wt *Curve.BIG, wm, privM []*Curve.BIG) (*Curve.ECP2, *Curve.ECP) {
	Aw := Curve.NewECP2()
	var Bw *Curve.ECP

	AwCh := make(chan interface{}, 1+len(privM))
	BwCh := make(chan interface{}, 1)

	cw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.G2(), wt) // (wt * g2)
	for i := range privM {
		cw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.Beta()[i], wm[i]) // wm[i] * beta[i]
	}

	cw.jobQueue <- jobpacket.MakeG1MulPacket(BwCh, h, wt) // wt * h

	Aw.Copy(vk.Alpha()) // Aw = alpha
	for i := 0; i <= len(privM); i++ {
		AwElemRes := <-AwCh
		Aw.Add(AwElemRes.(*Curve.ECP2)) // Aw = (wt * g2) + alpha + (wm[0] * beta[0]) + ... + (wm[i] * beta[i])
	}

	BwRes := <-BwCh
	Bw = BwRes.(*Curve.ECP) // Bw = wt * h

	return Aw, Bw
}

func (cw *CoconutWorker) reconstructKappaNuCommitments(params *MuxParams, vk *coconut.VerificationKey, sig *coconut.Signature, theta *coconut.Theta) (*Curve.ECP2, *Curve.ECP) {
	p := params.P()

	Aw := Curve.NewECP2()
	var Bw *Curve.ECP

	AwCh := make(chan interface{}, 3+len(theta.Proof().Rm()))
	BwCh := make(chan interface{}, 2)

	// Aw = (c * kappa)
	cw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, theta.Kappa(), theta.Proof().C())
	// Aw = (c * kappa) + (rt * g2)
	cw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.G2(), theta.Proof().Rt())
	// Aw = (c * kappa) + (rt * g2) + (-c * alpha)
	cw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.Alpha(), Curve.Modneg(theta.Proof().C(), p))
	for i := range theta.Proof().Rm() {
		// Aw = (c * kappa) + (rt * g2) + (-c * alpha) + (rm[0] * beta[0]) + ... + (rm[i] * beta[i])
		cw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.Beta()[i], theta.Proof().Rm()[i])
	}

	cw.jobQueue <- jobpacket.MakeG1MulPacket(BwCh, theta.Nu(), theta.Proof().C())
	cw.jobQueue <- jobpacket.MakeG1MulPacket(BwCh, sig.Sig1(), theta.Proof().Rt())

	Aw.Copy(vk.Alpha()) // this changes (-c * alpha) to ((1 - c) * alpha) as required
	for i := 0; i < 3+len(theta.Proof().Rm()); i++ {
		AwElemRes := <-AwCh
		Aw.Add(AwElemRes.(*Curve.ECP2))
	}

	BwRes1 := <-BwCh
	BwRes2 := <-BwCh
	Bw = BwRes1.(*Curve.ECP)    // Bw = (c * nu) OR Bw = (rt * h)
	Bw.Add(BwRes2.(*Curve.ECP)) // Bw = (c * nu) + (rt * h)

	return Aw, Bw
}

// ConstructVerifierProof creates a non-interactive zero-knowledge proof in order to prove corectness of kappa and nu.
// nolint: lll
func (cw *CoconutWorker) ConstructVerifierProof(params *MuxParams, vk *coconut.VerificationKey, sig *coconut.Signature, privM []*Curve.BIG, t *Curve.BIG) (*coconut.VerifierProof, error) {
	p, g1, g2, hs := params.P(), params.G1(), params.G2(), params.Hs()

	// witnesses creation
	params.Lock()
	wm := coconut.GetRandomNums(params.Params, len(privM))
	wt := coconut.GetRandomNums(params.Params, 1)[0]
	params.Unlock()

	Aw, Bw := cw.constructKappaNuCommitments(vk, sig.Sig1(), wt, wm, privM)

	tmpSlice := []utils.Printable{g1, g2, vk.Alpha(), Aw, Bw}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.Beta()))
	c, err := coconut.ConstructChallenge(ca)
	if err != nil {
		return nil, fmt.Errorf("Failed to construct challenge: %v", err)
	}

	// responses
	rm := coconut.CreateWitnessResponses(p, wm, c, privM)                            // rm[i] = (wm[i] - c * privM[i]) % o
	rt := coconut.CreateWitnessResponses(p, []*Curve.BIG{wt}, c, []*Curve.BIG{t})[0] // rt = (wt - c * t) % o

	return coconut.NewVerifierProof(c, rm, rt), nil
}

// VerifyVerifierProof verifies non-interactive zero-knowledge proofs in order to check corectness of kappa and nu.
// nolint: lll
func (cw *CoconutWorker) VerifyVerifierProof(params *MuxParams, vk *coconut.VerificationKey, sig *coconut.Signature, theta *coconut.Theta) bool {
	g1, g2, hs := params.G1(), params.G2(), params.Hs()

	Aw, Bw := cw.reconstructKappaNuCommitments(params, vk, sig, theta)

	tmpSlice := []utils.Printable{g1, g2, vk.Alpha(), Aw, Bw}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.Beta()))
	c, err := coconut.ConstructChallenge(ca)
	if err != nil {
		return false
	}

	return Curve.Comp(theta.Proof().C(), c) == 0
}

// ConstructTumblerProof constructs a zero knowledge proof required to
// implement Coconut's coin tumbler (https://arxiv.org/pdf/1802.07344.pdf).
// It proves knowledge of all private attributes in the credential and binds the proof to the address.
// Note that the first privM parameter HAS TO be coin's sequence number since the zeta is later revealed.
// loosely based on: https://github.com/asonnino/coconut-chainspace/blob/master/contracts/tumbler_proofs.py
// TODO: NEED SOMEBODY TO VERIFY CORECTNESS OF IMPLEMENTATION
// nolint: lll
func (cw *CoconutWorker) ConstructTumblerProof(params *MuxParams, vk *coconut.VerificationKey, sig *coconut.Signature, privM []*Curve.BIG, t *Curve.BIG, address []byte) (*coconut.TumblerProof, error) {
	p, g1, g2, hs := params.P(), params.G1(), params.G2(), params.Hs()

	// witnesses creation
	wm := coconut.GetRandomNums(params.Params, len(privM))
	wt := coconut.GetRandomNums(params.Params, 1)[0]

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
func (cw *CoconutWorker) VerifyTumblerProof(params *MuxParams, vk *coconut.VerificationKey, sig *coconut.Signature, theta *coconut.Theta, zeta *Curve.ECP, address []byte) bool {
	g1, g2, hs := params.G1(), params.G2(), params.Hs()

	CwCh := make(chan interface{}, 2)
	cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, g1, theta.Proof().Rm()[0])
	cw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, zeta, theta.Proof().C())

	Aw, Bw := cw.reconstructKappaNuCommitments(params, vk, sig, theta)

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
