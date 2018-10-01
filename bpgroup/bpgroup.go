// bpgroup.go - bilinear pairing wrapper
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

// Package bpgroup provides wrapper for groups and operations involved in the bilinear pairing
package bpgroup

import (
	"crypto/rand"

	"github.com/milagro-crypto/amcl/version3/go/amcl"
	Curve "github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// todo: consider replacing attributes with getters?
// todo: how many bytes of entropy

// BpGroup represents data required for a bilinear pairing
type BpGroup struct {
	Gen1 *Curve.ECP
	Gen2 *Curve.ECP2
	Ord  *Curve.BIG
	Rng  *amcl.RAND
}

// New returns a new instance of a BpGroup
func New() *BpGroup {
	rng := amcl.NewRAND()

	// amcl suggests using at least 128 bytes of entropy.
	// todo: is 256 enough for our needs?
	n := 256
	raw, err := generateRandomBytes(n)
	if err != nil {
		panic(err)
	}
	rng.Seed(n, raw)

	b := BpGroup{
		Gen1: Curve.ECP_generator(),
		Gen2: Curve.ECP2_generator(),
		Ord:  Curve.NewBIGints(Curve.CURVE_Order),
		Rng:  rng,
	}
	return &b
}

// Pair performs the bilinear pairing operation e(G1, G2) -> GT
func (b *BpGroup) Pair(g1 *Curve.ECP, g2 *Curve.ECP2) *Curve.FP12 {
	return Curve.Fexp(Curve.Ate(g2, g1))
}

// Returns slice of bytes of specified size of cryptographically secure random numbers.
// Refer to https://golang.org/pkg/crypto/rand/ for details regarding sources of entropy
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
