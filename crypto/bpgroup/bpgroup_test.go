// bpgroup_tests.go - tests for bilinear pairings
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
package bpgroup_test

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

// Check if the bilinearity property holds, i.e. e(aP, bQ) = e(P, Q)^ab
func TestPairing(t *testing.T) {
	G := bpgroup.New()

	P := Curve.G1mul(G.Gen1(), G.Order())
	assert.True(t, P.Is_infinity(), "rP != 0")

	Q := Curve.G2mul(G.Gen2(), G.Order())
	assert.True(t, Q.Is_infinity(), "rQ != 0")

	// generate random g1 and g2 elements
	x := Curve.Randomnum(G.Order(), G.Rng())
	y := Curve.Randomnum(G.Order(), G.Rng())

	P = Curve.G1mul(G.Gen1(), x)
	Q = Curve.G2mul(G.Gen2(), y)

	W := G.Pair(P, Q)

	g := Curve.GTpow(W, G.Order())
	assert.True(t, g.Isunity(), "g^r != 1")

	a := Curve.Randomnum(G.Order(), G.Rng())
	p := Curve.G1mul(P, a)
	gt1 := G.Pair(p, Q)
	gt2 := Curve.GTpow(G.Pair(P, Q), a)
	assert.True(t, gt1.Equals(gt2), "e(aP, Q) != e(P, Q)^a")

	a = Curve.Randomnum(G.Order(), G.Rng())
	q := Curve.G2mul(Q, a)
	gt1 = G.Pair(P, q)
	gt2 = Curve.GTpow(G.Pair(P, Q), a)
	assert.True(t, gt1.Equals(gt2), "e(P, aQ) != e(P, Q)^a")

	a = Curve.Randomnum(G.Order(), G.Rng())
	p = Curve.G1mul(P, a)
	q = Curve.G2mul(Q, a)
	gt1 = G.Pair(P, q)
	gt2 = G.Pair(p, Q)
	assert.True(t, gt1.Equals(gt2), "e(aP, Q) != e(P, aQ)")

	a = Curve.Randomnum(G.Order(), G.Rng())
	b := Curve.Randomnum(G.Order(), G.Rng())
	p = Curve.G1mul(P, a)
	q = Curve.G2mul(Q, b)
	c := Curve.Modmul(a, b, G.Order())
	gt1 = G.Pair(p, q)
	gt2 = Curve.GTpow(G.Pair(P, Q), c)
	assert.True(t, gt1.Equals(gt2), "e(aP, bQ) != e(P, Q)^ab")
}

//nolint: gochecknoglobals
var g1Mulres *Curve.ECP

func BenchmarkG1Mul(b *testing.B) {
	G := bpgroup.New()
	var res *Curve.ECP
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// generate random g1 elem which is not the generator
		r := Curve.Randomnum(G.Order(), G.Rng())
		rg1 := Curve.G1mul(G.Gen1(), r)
		t := Curve.Randomnum(G.Order(), G.Rng())
		b.StartTimer()
		res = Curve.G1mul(rg1, t)
	}
	// it is recommended to store results in package level variables,
	// so that compiler would not try to optimise the benchmark
	g1Mulres = res
}

//nolint: gochecknoglobals
var g2MulRes *Curve.ECP2

func BenchmarkG2Mul(b *testing.B) {
	G := bpgroup.New()
	var res *Curve.ECP2
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// generate random g12elem which is not the generator
		r := Curve.Randomnum(G.Order(), G.Rng())
		rg2 := Curve.G2mul(G.Gen2(), r)
		t := Curve.Randomnum(G.Order(), G.Rng())
		b.StartTimer()
		res = Curve.G2mul(rg2, t)
	}
	// it is recommended to store results in package level variables,
	// so that compiler would not try to optimise the benchmark
	g2MulRes = res
}

//nolint: gochecknoglobals
var pairRes *Curve.FP12

func BenchmarkPairing(b *testing.B) {
	G := bpgroup.New()
	var res *Curve.FP12
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// generate random g1 and g2 elems which are not the generators
		r1 := Curve.Randomnum(G.Order(), G.Rng())
		rg1 := Curve.G1mul(G.Gen1(), r1)

		r2 := Curve.Randomnum(G.Order(), G.Rng())
		rg2 := Curve.G2mul(G.Gen2(), r2)
		b.StartTimer()
		res = G.Pair(rg1, rg2)
	}
	// it is recommended to store results in package level variables,
	// so that compiler would not try to optimise the benchmark
	pairRes = res
}
