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
	"github.com/jstuczyn/CoconutGo/crypto/elgamal"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// ElGamalKeygen generates private and public keys required for ElGamal encryption scheme.
func (ccw *Worker) ElGamalKeygen(params *MuxParams) (*elgamal.PrivateKey, *elgamal.PublicKey) {
	params.Lock()
	pk, pub := elgamal.Keygen(params.Params.G)
	params.Unlock()
	return pk, pub
}

// ElGamalEncrypt encrypts the given message in the form of h^m,
// where h is a point on the G1 curve using the given public key.
// The random k is returned alongside the encryption
// as it is required by the Coconut Scheme to create proofs of knowledge.
// nolint: lll
func (ccw *Worker) ElGamalEncrypt(params *MuxParams, pub *elgamal.PublicKey, m *Curve.BIG, h *Curve.ECP) *elgamal.EncryptionResult {
	// we had a choice of either having multiple encryptions in parallel or g1muls inside them
	// having both would require changing entire worker structure to perhaps have some priority queues
	// and somehow detect deadlocks (say there's a single worker which works on encryption, then it spawns G1mulpacket,
	// which worker is gonna read it and how if they are stuck waiting for said results?)
	gamma, p, g1, rng := pub.Gamma, params.P(), params.G1(), params.G.Rng()

	params.Lock()
	k := Curve.Randomnum(p, rng)
	params.Unlock()

	a := Curve.G1mul(g1, k)
	b := Curve.G1mul(gamma, k) // b = (k * gamma)
	b.Add(Curve.G1mul(h, m))   // b = (k * gamma) + (m * h)

	return elgamal.NewEncryptionResult(elgamal.NewEncryptionFromPoints(a, b), k)
}

// makeElGamalEncryptionOp returns a function with signature of func() (interface{}, error),
// so that it could be performed by job workers.
// Ideally this method should have been changed into function and placed in jobpacket package,
// but that would cause a cyclic dependency (coconutclient imports jobpacket already).
// nolint: lll
func (ccw *Worker) makeElGamalEncryptionOp(params *MuxParams, pub *elgamal.PublicKey, m *Curve.BIG, h *Curve.ECP) func() (interface{}, error) {
	return func() (interface{}, error) {
		return ccw.ElGamalEncrypt(params, pub, m, h), nil
	}
}

// ElGamalDecrypt takes the ElGamal encryption of a message and returns a point on the G1 curve
// that represents original h^m.
func (ccw *Worker) ElGamalDecrypt(params *MuxParams, pk *elgamal.PrivateKey, enc *elgamal.Encryption) *Curve.ECP {
	return elgamal.Decrypt(params.Params.G, pk, enc)
}
