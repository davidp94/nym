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

// Package coconutclientworker provides the functionalities required to use the Coconut scheme concurrently
package coconutclientworker

import (
	"sync"

	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobpacket"

	"github.com/jstuczyn/CoconutGo/coconut/scheme"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// MuxParams is identical to normal params, but has an attached mutex, so that
// rng in bpgroup could be shared safely.
type MuxParams struct {
	coconut.Params
	mux sync.Mutex
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

// Verify verifies the Coconut credential that has been either issued exlusiviely on public attributes
// or all private attributes have been publicly revealed
func (ccw *CoconutClientWorker) Verify(params *coconut.Params, vk *coconut.VerificationKey, pubM []*Curve.BIG, sig *coconut.Signature) bool {
	if len(pubM) != len(vk.Beta()) {
		return false
	}

	K := Curve.NewECP2()
	K.Copy(vk.Alpha()) // K = X

	// create buffered channel so that workers could immediately start next job
	// packet without waiting for read from the master (if multiple writes)
	outChG1Mul := make(chan interface{}, len(pubM))

	// in this case ordering does not matter at all, since we're adding all results together
	for i := 0; i < len(pubM); i++ {
		// change structure of jobpacket to fix that monstrosity...
		ccw.jobQueue <- jobpacket.MakeG2MulPacket(outChG1Mul, vk.Beta()[i], pubM[i])
	}
	for i := 0; i < len(pubM); i++ {
		res := <-outChG1Mul
		g2E := res.(*Curve.ECP2)
		K.Add(g2E) // K = X + (a1 * Y1) + ...
	}

	outChPair := make(chan interface{}, 2)
	ccw.jobQueue <- jobpacket.MakePairingPacket(outChPair, sig.Sig1(), K)
	ccw.jobQueue <- jobpacket.MakePairingPacket(outChPair, sig.Sig2(), vk.G2())

	// we can evaluate that while waiting for valuation of both pairings
	exp1 := !sig.Sig1().Is_infinity()

	res1 := <-outChPair
	res2 := <-outChPair
	gt1 := res1.(*Curve.FP12)
	gt2 := res2.(*Curve.FP12)

	exp2 := gt1.Equals(gt2)
	return exp1 && exp2
}

// New creates new instance of the CoconutClientWorker.
func New(jobQueue chan<- interface{}) *CoconutClientWorker {
	return &CoconutClientWorker{
		jobQueue: jobQueue,
	}
}
