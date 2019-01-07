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

	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// BpGroup represents data required for a bilinear pairing
type BpGroup struct {
	gen1 *Curve.ECP
	gen2 *Curve.ECP2
	ord  *Curve.BIG
	rng  *amcl.RAND
}

// Gen1 returns generator for G1
func (b *BpGroup) Gen1() *Curve.ECP {
	return b.gen1
}

// Gen2 returns generator for G2
func (b *BpGroup) Gen2() *Curve.ECP2 {
	return b.gen2
}

// Order returns order of the group
func (b *BpGroup) Order() *Curve.BIG {
	return b.ord
}

// Rng returns instance of random number generator
func (b *BpGroup) Rng() *amcl.RAND {
	return b.rng
}

// Pair performs the bilinear pairing operation e(G1, G2) -> GT
func (b *BpGroup) Pair(g1 *Curve.ECP, g2 *Curve.ECP2) *Curve.FP12 {
	return Curve.Fexp(Curve.Ate(g2, g1))
}

// New returns a new instance of a BpGroup
func New() *BpGroup {
	rng := amcl.NewRAND()
	n := 256
	raw, err := generateRandomBytes(n)
	if err != nil {
		panic(err)
	}
	rng.Seed(n, raw)

	b := BpGroup{
		gen1: Curve.ECP_generator(),
		gen2: Curve.ECP2_generator(),
		ord:  Curve.NewBIGints(Curve.CURVE_Order),
		rng:  rng,
	}
	return &b
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
