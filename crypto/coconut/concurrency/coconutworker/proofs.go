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
	"github.com/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/utils"
	"github.com/jstuczyn/CoconutGo/crypto/elgamal"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// ConstructSignerProof creates a non-interactive zero-knowledge proof to prove corectness of ciphertexts and cm.
// nolint: lll, gocyclo
func (ccw *Worker) ConstructSignerProof(params *MuxParams, gamma *Curve.ECP, encs []*elgamal.Encryption, cm *Curve.ECP, k []*Curve.BIG, r *Curve.BIG, pubM []*Curve.BIG, privM []*Curve.BIG) (*coconut.SignerProof, error) {
	p, g1, g2, hs, rng := params.P(), params.G1(), params.G2(), params.Hs(), params.G.Rng()

	attributes := append(privM, pubM...)
	if len(encs) != len(k) || len(encs) != len(privM) {
		return nil, coconut.ErrConstructSignerCiphertexts
	}
	if len(attributes) > len(hs) {
		return nil, coconut.ErrConstructSignerAttrs
	}

	// witnesses creation
	params.Lock()
	wr := Curve.Randomnum(p, rng)
	wk := make([]*Curve.BIG, len(k))
	wm := make([]*Curve.BIG, len(attributes))

	for i := range k {
		wk[i] = Curve.Randomnum(p, rng)
	}
	for i := range attributes {
		wm[i] = Curve.Randomnum(p, rng)
	}
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
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(AwChs[i], g1, wk[i]) // Aw[i] = (wk[i] * g1)
	}

	for i := range wk {
		// buf for 2 - (wm[i] * h) AND (wk[i] * gamma) - order does not matter because they're added together later
		BwChs[i] = make(chan interface{}, 2)
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], h, wm[i])
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], gamma, wk[i])
	}

	ccw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, g1, wr)
	for i := range attributes {
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, hs[i], wm[i])
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
	ca := make([]utils.Printable, len(tmpSlice)+len(hs)+len(Aw)+len(Bw))
	i := copy(ca, tmpSlice)

	// can't use copy for those due to type difference (utils.Printable vs *Curve.ECP)
	for _, item := range hs {
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

	c := coconut.ConstructChallenge(ca)

	// responses
	rr := wr.Minus(Curve.Modmul(c, r, p))
	rr = rr.Plus(p)
	rr.Mod(p) // rr = (wr - c * r) % o

	rk := make([]*Curve.BIG, len(wk))
	for i := range wk {
		rk[i] = wk[i].Minus(Curve.Modmul(c, k[i], p))
		rk[i] = rk[i].Plus(p)
		rk[i].Mod(p) // rk[i] = (wk[i] - c * k[i]) % o
	}

	rm := make([]*Curve.BIG, len(wm))
	for i := range wm {
		rm[i] = wm[i].Minus(Curve.Modmul(c, attributes[i], p))
		rm[i] = rm[i].Plus(p)
		rm[i].Mod(p) // rm[i] = (wm[i] - c * attributes[i]) % o
	}

	return coconut.NewSignerProof(c, rr, rk, rm), nil
}

// VerifySignerProof verifies non-interactive zero-knowledge proofs in order to check corectness of ciphertexts and cm.
func (ccw *Worker) VerifySignerProof(params *MuxParams, gamma *Curve.ECP, signMats *coconut.BlindSignMats) bool {
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
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(AwChs[i], encs[i].C1(), proof.C())
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(AwChs[i], g1, proof.Rk()[i])
	}

	for i := range encs {
		BwChs[i] = make(chan interface{}, 3) // buf for 3 - (c * c2[i]) AND (rk[i] * gamma) AND (rm[i] * h)
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], encs[i].C2(), proof.C())
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], gamma, proof.Rk()[i])
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(BwChs[i], h, proof.Rm()[i])
	}

	ccw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, cm, proof.C())
	ccw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, g1, proof.Rr())
	for i := range proof.Rm() {
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(CwCh, hs[i], proof.Rm()[i])
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
	ca := make([]utils.Printable, len(tmpSlice)+len(hs)+len(Aw)+len(Bw))
	i := copy(ca, tmpSlice)

	// can't use copy for those due to type difference (utils.Printable vs *Curve.ECP)
	for _, item := range hs {
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

	return Curve.Comp(proof.C(), coconut.ConstructChallenge(ca)) == 0
}

// ConstructVerifierProof creates a non-interactive zero-knowledge proof in order to prove corectness of kappa and nu.
// nolint: lll
func (ccw *Worker) ConstructVerifierProof(params *MuxParams, vk *coconut.VerificationKey, sig *coconut.Signature, privM []*Curve.BIG, t *Curve.BIG) *coconut.VerifierProof {
	p, g1, g2, hs, rng := params.P(), params.G1(), params.G2(), params.Hs(), params.G.Rng()

	// witnesses creation
	params.Lock()
	wm := make([]*Curve.BIG, len(privM))
	for i := 0; i < len(privM); i++ {
		wm[i] = Curve.Randomnum(p, rng)
	}
	wt := Curve.Randomnum(p, rng)
	params.Unlock()

	// witnesses commitments
	Aw := Curve.NewECP2()
	var Bw *Curve.ECP

	AwCh := make(chan interface{}, 1+len(privM))
	BwCh := make(chan interface{}, 1)

	ccw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, g2, wt)
	for i := range privM {
		ccw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.Beta()[i], wm[i])
	}

	ccw.jobQueue <- jobpacket.MakeG1MulPacket(BwCh, sig.Sig1(), wt)

	Aw.Copy(vk.Alpha())
	for i := 0; i <= len(privM); i++ {
		AwElemRes := <-AwCh
		Aw.Add(AwElemRes.(*Curve.ECP2)) // Aw = (wt * g2) + alpha + (wm[0] * beta[0]) + ... + (wm[i] * beta[i])
	}

	BwRes := <-BwCh
	Bw = BwRes.(*Curve.ECP) // Bw = wt * h

	tmpSlice := []utils.Printable{g1, g2, vk.Alpha(), Aw, Bw}
	ca := make([]utils.Printable, len(tmpSlice)+len(hs)+len(vk.Beta()))
	i := copy(ca, tmpSlice)

	// can't use copy for those due to type difference (utils.Printable vs *Curve.ECP and *Curve.ECP2)
	for _, item := range hs {
		ca[i] = item
		i++
	}
	for _, item := range vk.Beta() {
		ca[i] = item
		i++
	}

	c := coconut.ConstructChallenge(ca)

	// responses
	rm := make([]*Curve.BIG, len(privM))
	for i := range privM {
		rm[i] = wm[i].Minus(Curve.Modmul(c, privM[i], p))
		rm[i] = rm[i].Plus(p)
		rm[i].Mod(p)
	}

	rt := wt.Minus(Curve.Modmul(c, t, p))
	rt = rt.Plus(p)
	rt.Mod(p)

	return coconut.NewVerifierProof(c, rm, rt)
}

// VerifyVerifierProof verifies non-interactive zero-knowledge proofs in order to check corectness of kappa and nu.
// nolint: lll
func (ccw *Worker) VerifyVerifierProof(params *MuxParams, vk *coconut.VerificationKey, sig *coconut.Signature, showMats *coconut.BlindShowMats) bool {
	p, g1, g2, hs := params.P(), params.G1(), params.G2(), params.Hs()

	Aw := Curve.NewECP2()
	var Bw *Curve.ECP

	AwCh := make(chan interface{}, 3+len(showMats.Proof().Rm()))
	BwCh := make(chan interface{}, 2)

	// Aw = (c * kappa)
	ccw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, showMats.Kappa(), showMats.Proof().C())
	// Aw = (c * kappa) + (rt * g2)
	ccw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.G2(), showMats.Proof().Rt())
	// Aw = (c * kappa) + (rt * g2) + (-c * alpha)
	ccw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.Alpha(), Curve.Modneg(showMats.Proof().C(), p))
	for i := range showMats.Proof().Rm() {
		// Aw = (c * kappa) + (rt * g2) + (-c * alpha) + (rm[0] * beta[0]) + ... + (rm[i] * beta[i])
		ccw.jobQueue <- jobpacket.MakeG2MulPacket(AwCh, vk.Beta()[i], showMats.Proof().Rm()[i])
	}

	ccw.jobQueue <- jobpacket.MakeG1MulPacket(BwCh, showMats.Nu(), showMats.Proof().C())
	ccw.jobQueue <- jobpacket.MakeG1MulPacket(BwCh, sig.Sig1(), showMats.Proof().Rt())

	Aw.Copy(vk.Alpha()) // this changes (-c * alpha) to ((1 - c) * alpha) as required
	for i := 0; i < 3+len(showMats.Proof().Rm()); i++ {
		AwElemRes := <-AwCh
		Aw.Add(AwElemRes.(*Curve.ECP2))
	}

	BwRes1 := <-BwCh
	BwRes2 := <-BwCh
	Bw = BwRes1.(*Curve.ECP)    // Bw = (c * nu) OR Bw = (rt * h)
	Bw.Add(BwRes2.(*Curve.ECP)) // Bw = (c * nu) + (rt * h)

	tmpSlice := []utils.Printable{g1, g2, vk.Alpha(), Aw, Bw}
	ca := make([]utils.Printable, len(tmpSlice)+len(hs)+len(vk.Beta()))
	i := copy(ca, tmpSlice)

	// can't use copy for those due to type difference (utils.Printable vs *Curve.ECP and *Curve.ECP2)
	for _, item := range hs {
		ca[i] = item
		i++
	}
	for _, item := range vk.Beta() {
		ca[i] = item
		i++
	}

	return Curve.Comp(showMats.Proof().C(), coconut.ConstructChallenge(ca)) == 0
}
