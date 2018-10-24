// elgamal.go - Worker for the Coconut scheme
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

// Package coconutclient provides the functionalities required to use the Coconut scheme concurrently.
package coconutclient

import (
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobpacket"
	"github.com/jstuczyn/CoconutGo/elgamal"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// todo: reimplement keygen and decrypt with putting g1^d to jobqueue? - needs performance testing whether it is worth it.

// ElGamalKeygen generates private and public keys required for ElGamal encryption scheme.
func (ccw *Worker) ElGamalKeygen(params *MuxParams) (*Curve.BIG, *Curve.ECP) {
	params.Lock()
	d, gamma := elgamal.Keygen(params.Params.G)
	params.Unlock()
	return d, gamma
}

// ElGamalEncrypt encrypts the given message in the form of h^m,
// where h is a point on the G1 curve using the given public key.
// The random k is returned alongside the encryption
// as it is required by the Coconut Scheme to create proofs of knowledge.
func (ccw *Worker) ElGamalEncrypt(params *MuxParams, gamma *Curve.ECP, m *Curve.BIG, h *Curve.ECP) (*elgamal.Encryption, *Curve.BIG) {
	p, g1, rng := params.P(), params.G1(), params.G.Rng()

	params.Lock()
	k := Curve.Randomnum(p, rng)
	params.Unlock()

	aCh := make(chan interface{}, 1)
	bCh := make(chan interface{}, 2)
	ccw.jobQueue <- jobpacket.MakeG1MulPacket(aCh, g1, k)
	ccw.jobQueue <- jobpacket.MakeG1MulPacket(bCh, gamma, k)
	ccw.jobQueue <- jobpacket.MakeG1MulPacket(bCh, h, m)

	aRes := <-aCh
	a := aRes.(*Curve.ECP)

	bRes1 := <-bCh
	bRes2 := <-bCh

	b := bRes1.(*Curve.ECP)   // b = (k * gamma) OR b = (m * h)
	b.Add(bRes2.(*Curve.ECP)) // b = (k * gamma) + (m * h)

	return elgamal.NewEncryptionFromPoints(a, b), k
}

// ElGamalDecrypt takes the ElGamal encryption of a message and returns a point on the G1 curve
// that represents original h^m.
func (ccw *Worker) ElGamalDecrypt(params *MuxParams, d *Curve.BIG, enc *elgamal.Encryption) *Curve.ECP {
	return elgamal.Decrypt(params.Params.G, d, enc)
}
