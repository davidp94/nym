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

	"github.com/jstuczyn/CoconutGo/bpgroup"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BN254"
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
