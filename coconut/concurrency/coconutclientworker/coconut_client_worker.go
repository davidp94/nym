// coconut_client_worker.go - Worker for the Coconut scheme
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

// Package coconutclientworker provides the functionalities required to use the Coconut scheme concurrently.
package coconutclientworker

import (
	"sync"

	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobpacket"
	"github.com/jstuczyn/CoconutGo/coconut/utils"

	"github.com/jstuczyn/CoconutGo/coconut/scheme"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// MuxParams is identical to normal params, but has an attached mutex, so that
// rng in bpgroup could be shared safely.
type MuxParams struct {
	coconut.Params
	sync.Mutex
}

// CoconutClientWorker allows writing coconut actions to a shared job queue,
// so that they could be run concurrently.
// todo: introduce more attributes as needed, perhaps keep params here?
type CoconutClientWorker struct {
	jobQueue chan<- interface{}
}

// Setup generates the public parameters required by the Coconut scheme.
// q indicates the maximum number of attributes that can be embed in the credentials.
func (ccw *CoconutClientWorker) Setup(q int) (*MuxParams, error) {
	// each hashing operation takes ~3ms, which is not neccesarily worth parallelizing
	// due to increased code complexity especially since Setup is only run once
	params, err := coconut.Setup(q)
	if err != nil {
		return nil, err
	}
	return &MuxParams{*params, sync.Mutex{}}, nil
}

// Keygen generates a single Coconut keypair ((x, y1, y2...), (g2, g2^x, g2^y1, ...)).
// It is not suitable for threshold credentials as all generated keys are independent of each other.
func (ccw *CoconutClientWorker) Keygen(params *MuxParams) (*coconut.SecretKey, *coconut.VerificationKey, error) {
	p, g2, hs, rng := params.P(), params.G2(), params.Hs(), params.G.Rng()

	q := len(hs)
	if q < 1 {
		return nil, nil, coconut.ErrKeygenParams
	}
	// normal sk generation
	x := Curve.Randomnum(p, rng)
	y := make([]*Curve.BIG, q)
	for i := 0; i < q; i++ {
		y[i] = Curve.Randomnum(p, rng)
	}
	sk := coconut.NewSk(x, y)

	alphaCh := make(chan interface{}, 1)
	ccw.jobQueue <- jobpacket.MakeG2MulPacket(alphaCh, g2, x)

	// unlike other G2muls where results are then added together,
	// ordering matters here, so we can't just use buffered channels
	beta := make([]*Curve.ECP2, q)
	betaChs := make([]chan interface{}, q)
	for i := range betaChs {
		betaChs[i] = make(chan interface{}, 1)
		ccw.jobQueue <- jobpacket.MakeG2MulPacket(betaChs[i], g2, y[i])
	}

	// all jobs are in the queue, so it doesn't matter in which order we read results
	// as we need all of them and each results has dedicated channel, so nothing is blocked
	alphaRes := <-alphaCh
	alpha := alphaRes.(*Curve.ECP2)

	for i := 0; i < q; i++ {
		betaRes := <-betaChs[i]
		beta[i] = betaRes.(*Curve.ECP2)
	}

	vk := coconut.NewVk(g2, alpha, beta)
	return sk, vk, nil
}

// TTPKeygen generates a set of n Coconut keypairs [((x, y1, y2...), (g2, g2^x, g2^y1, ...)), ...],
// such that they support threshold aggregation of t parties.
// It is expected that this procedure is executed by a Trusted Third Party.
func (ccw *CoconutClientWorker) TTPKeygen(params *MuxParams, t int, n int) ([]*coconut.SecretKey, []*coconut.VerificationKey, error) {
	p, g2, hs, rng := params.P(), params.G2(), params.Hs(), params.G.Rng()

	q := len(hs)
	if n < t || t <= 0 || q <= 0 {
		return nil, nil, coconut.ErrTTPKeygenParams
	}

	// polynomials generation
	v := utils.GenerateRandomBIGSlice(p, rng, t)
	w := make([][]*Curve.BIG, q)
	for i := range w {
		w[i] = utils.GenerateRandomBIGSlice(p, rng, t)
	}

	// secret keys - nothing (relatively) computationally expensive here
	sks := make([]*coconut.SecretKey, n)
	for i := 1; i < n+1; i++ {
		iBIG := Curve.NewBIGint(i)
		x := utils.PolyEval(v, iBIG, p)
		ys := make([]*Curve.BIG, q)
		for j, wj := range w {
			ys[j] = utils.PolyEval(wj, iBIG, p)
		}
		sks[i-1] = coconut.NewSk(x, ys)
	}

	alphaChs := make([]chan interface{}, n)
	betaChs := make([][]chan interface{}, n)
	for i := range sks {
		alphaChs[i] = make(chan interface{}, 1)
		ccw.jobQueue <- jobpacket.MakeG2MulPacket(alphaChs[i], g2, sks[i].X())

		betaChs[i] = make([]chan interface{}, q)
		for j, yj := range sks[i].Y() {
			betaChs[i][j] = make(chan interface{}, 1)
			ccw.jobQueue <- jobpacket.MakeG2MulPacket(betaChs[i][j], g2, yj)
		}
	}

	vks := make([]*coconut.VerificationKey, n)
	for i := range sks {
		alphaRes := <-alphaChs[i]
		alpha := alphaRes.(*Curve.ECP2)

		beta := make([]*Curve.ECP2, q)
		for j := 0; j < q; j++ {
			betaijRes := <-betaChs[i][j]
			beta[j] = betaijRes.(*Curve.ECP2)
		}
		vks[i] = coconut.NewVk(g2, alpha, beta)
	}
	return sks, vks, nil
}

// Sign creates a Coconut credential under a given secret key on a set of public attributes only.
func (ccw *CoconutClientWorker) Sign(params *MuxParams, sk *coconut.SecretKey, pubM []*Curve.BIG) (*coconut.Signature, error) {
	// there are no expensive operations that could be parallelized in sign
	return coconut.Sign(&params.Params, sk, pubM)
}

// Verify verifies the Coconut credential that has been either issued exlusiviely on public attributes
// or all private attributes have been publicly revealed
func (ccw *CoconutClientWorker) Verify(params *MuxParams, vk *coconut.VerificationKey, pubM []*Curve.BIG, sig *coconut.Signature) bool {
	if len(pubM) != len(vk.Beta()) {
		return false
	}

	K := Curve.NewECP2()
	K.Copy(vk.Alpha()) // K = X

	// create buffered channel so that workers could immediately start next job
	// packet without waiting for read from the master (if multiple writes)
	outChG2Mul := make(chan interface{}, len(pubM))

	// in this case ordering does not matter at all, since we're adding all results together
	for i := 0; i < len(pubM); i++ {
		ccw.jobQueue <- jobpacket.MakeG2MulPacket(outChG2Mul, vk.Beta()[i], pubM[i])
	}
	for i := 0; i < len(pubM); i++ {
		res := <-outChG2Mul
		g2E := res.(*Curve.ECP2)
		K.Add(g2E) // K = X + (a1 * Y1) + ...
	}

	outChPair := make(chan interface{}, 2)
	ccw.jobQueue <- jobpacket.MakePairingPacket(outChPair, sig.Sig1(), K)
	ccw.jobQueue <- jobpacket.MakePairingPacket(outChPair, sig.Sig2(), vk.G2())

	res1 := <-outChPair
	res2 := <-outChPair
	gt1 := res1.(*Curve.FP12)
	gt2 := res2.(*Curve.FP12)

	return !sig.Sig1().Is_infinity() && gt1.Equals(gt2)
}

// Randomize randomizes the Coconut credential such that it becomes indistinguishable
// from a fresh credential on different attributes
func (ccw *CoconutClientWorker) Randomize(params *MuxParams, sig *coconut.Signature) *coconut.Signature {
	p, rng := params.P(), params.G.Rng()

	params.Lock()
	t := Curve.Randomnum(p, rng)
	params.Unlock()

	sig1Ch := make(chan interface{}, 1)
	sig2Ch := make(chan interface{}, 1)

	ccw.jobQueue <- jobpacket.MakeG1MulPacket(sig1Ch, sig.Sig1(), t)
	ccw.jobQueue <- jobpacket.MakeG1MulPacket(sig2Ch, sig.Sig2(), t)

	sig1Res := <-sig1Ch
	sig2Res := <-sig2Ch

	return coconut.NewSignature(sig1Res.(*Curve.ECP), sig2Res.(*Curve.ECP))
}

// AggregateVerificationKeys aggregates verification keys of the signing authorities.
// Optionally it does so in a threshold manner.
func (ccw *CoconutClientWorker) AggregateVerificationKeys(params *MuxParams, vks []*coconut.VerificationKey, pp *coconut.PolynomialPoints) *coconut.VerificationKey {
	// no point in repeating code as this bit can't benefit from concurrency anyway
	if pp == nil {
		return coconut.AggregateVerificationKeys(&params.Params, vks, nil)
	}

	// threshold aggregation
	t := len(vks)
	if t <= 0 {
		return nil
	}
	p := params.P()
	q := len(vks[0].Beta())

	alpha := Curve.NewECP2()
	beta := make([]*Curve.ECP2, q)
	for i := range beta {
		beta[i] = Curve.NewECP2()
	}

	li := make([]*Curve.BIG, t)
	for i := 0; i < t; i++ {
		li[i] = utils.LagrangeBasis(i, p, pp.Xs(), 0)
	}

	alphaCh := make(chan interface{}, t)
	// make q channels (for each attribute) with buffer of t
	betaChs := make([]chan interface{}, q)
	for i := range betaChs {
		betaChs[i] = make(chan interface{}, t)
	}
	for i := 0; i < t; i++ {
		ccw.jobQueue <- jobpacket.MakeG2MulPacket(alphaCh, vks[i].Alpha(), li[i])
		for j, betaj := range vks[i].Beta() {
			ccw.jobQueue <- jobpacket.MakeG2MulPacket(betaChs[j], betaj, li[i])
		}
	}

	for i := 0; i < t; i++ {
		alphaRes := <-alphaCh
		alpha.Add(alphaRes.(*Curve.ECP2))
	}

	for i := 0; i < t; i++ {
		for j := 0; j < len(beta); j++ {
			betaRes := <-betaChs[j]
			beta[j].Add(betaRes.(*Curve.ECP2))
		}
	}

	return coconut.NewVk(vks[0].G2(), alpha, beta)
}

// AggregateSignatures aggregates Coconut credentials on the same set of attributes
// that were produced by multiple signing authorities.
// Optionally it does so in a threshold manner.
func (ccw *CoconutClientWorker) AggregateSignatures(params *MuxParams, sigs []*coconut.Signature, pp *coconut.PolynomialPoints) *coconut.Signature {
	// no point in repeating code as this bit can't benefit from concurrency anyway
	if pp == nil {
		return coconut.AggregateSignatures(&params.Params, sigs, nil)
	}

	t := len(sigs)
	if t <= 0 {
		return nil
	}
	p := params.P()
	sig2 := Curve.NewECP()
	l := utils.GenerateLagrangianCoefficients(t, p, pp.Xs(), 0)

	sig2Ch := make(chan interface{}, t)
	for i := 0; i < t; i++ {
		ccw.jobQueue <- jobpacket.MakeG1MulPacket(sig2Ch, sigs[i].Sig2(), l[i])
	}

	for i := 0; i < t; i++ {
		sig2Res := <-sig2Ch
		sig2.Add(sig2Res.(*Curve.ECP))
	}

	return coconut.NewSignature(sigs[0].Sig1(), sig2)
}

// New creates new instance of the CoconutClientWorker.
func New(jobQueue chan<- interface{}) *CoconutClientWorker {
	return &CoconutClientWorker{
		jobQueue: jobQueue,
	}
}
