// elgamal.go - ElGamal encryption scheme
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

// Package elgamal provides primitives required by the ElGamal encryption scheme.
// It's based on Python's implementation: https://github.com/asonnino/coconut/blob/master/coconut/utils.py.
package elgamal

import (
	"github.com/jstuczyn/CoconutGo/bpgroup"
	// The named import is used to be able to easily update curve being used
	Curve "github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// todo: rename to just 'Encryption' since it is already in elgamal package
// todo: create types for public and private keys and adjust arguments accordingly (look https://godoc.org/golang.org/x/crypto/openpgp/elgamal)
// todo: rather than pass entire BpGroup object, pass just rng gen, like the above implementation
// todo: rename A and B in Encryption to c1 and c2 as is usually used in literature
// todo: make A and B (or c1, c2) private and introduce getters
// todo: possibly alternative version of Decrypt to return actual m rather than h^m

// ElGamalEncryption are the two points on the G1 curve
// that represent encryption of message in form of h^m
type ElGamalEncryption struct {
	A *Curve.ECP
	B *Curve.ECP
}

// Keygen generates private and public keys required for ElGamal encryption scheme
func Keygen(G *bpgroup.BpGroup) (*Curve.BIG, *Curve.ECP) {
	d := Curve.Randomnum(G.Ord, G.Rng)
	gamma := Curve.G1mul(G.Gen1, d)
	return d, gamma
}

// Encrypt encrypts the given message in the form of h^m,
// where h is a point on the G1 curve using the given public key.
// The random k is returned alongside the encryption
// as it is required by the Coconut Scheme to create proofs of knowledge.
func Encrypt(G *bpgroup.BpGroup, gamma *Curve.ECP, m *Curve.BIG, h *Curve.ECP) (*ElGamalEncryption, *Curve.BIG) {
	k := Curve.Randomnum(G.Ord, G.Rng)
	a := Curve.G1mul(G.Gen1, k)
	b := Curve.G1mul(gamma, k) // b = (k * gamma)
	b.Add(Curve.G1mul(h, m))   // b = (k * gamma) + (m * h)

	return &ElGamalEncryption{a, b}, k
}

// Decrypt takes the ElGamal encryption of a message and returns a point on the G1 curve
// that represents original h^m.
func Decrypt(G *bpgroup.BpGroup, d *Curve.BIG, enc *ElGamalEncryption) *Curve.ECP {
	dec := Curve.NewECP()
	dec.Copy(enc.B)
	dec.Sub(Curve.G1mul(enc.A, d))
	return dec
}
