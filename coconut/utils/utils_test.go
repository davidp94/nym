// utils_test.go - utils tests
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
package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BN254"
)

// nolint: lll
func TestPolyEval(t *testing.T) {
	order := Curve.NewBIGints(Curve.CURVE_Order)
	tests := []struct {
		coeff    []*Curve.BIG
		x        *Curve.BIG
		o        *Curve.BIG
		expected *Curve.BIG
	}{
		{coeff: []*Curve.BIG{Curve.NewBIGint(20), Curve.NewBIGint(21), Curve.NewBIGint(42)},
			x:        Curve.NewBIGint(0),
			o:        order,
			expected: Curve.NewBIGint(20),
		},
		{coeff: []*Curve.BIG{Curve.NewBIGint(0), Curve.NewBIGint(0), Curve.NewBIGint(0)},
			x:        Curve.NewBIGint(4),
			o:        order,
			expected: Curve.NewBIGint(0),
		},
		{coeff: []*Curve.BIG{Curve.NewBIGint(1), Curve.NewBIGint(2), Curve.NewBIGint(3), Curve.NewBIGint(4), Curve.NewBIGint(5)},
			x:        Curve.NewBIGint(10),
			o:        order,
			expected: Curve.NewBIGint(54321),
		},
	}

	for _, test := range tests {
		comp := Curve.Comp(test.expected, utils.PolyEval(test.coeff, test.x, test.o))
		assert.Zero(t, comp)
	}
}

func TestLagrangeBasis(t *testing.T) {
	// polynomial of order k - 1
	G := bpgroup.New()
	p, rng := G.Order(), G.Rng()
	ks := []int{1, 3, 5, 10}
	for _, k := range ks {
		v := make([]*Curve.BIG, k)
		ls := make([]*Curve.BIG, k)
		vals := make([]*Curve.BIG, k)
		xs := make([]*Curve.BIG, k)
		for i := range v {
			v[i] = Curve.Randomnum(p, rng)
			xs[i] = Curve.Randomnum(p, rng) // works for any xs
		}
		for i := range v {
			ls[i] = utils.LagrangeBasis(i, p, xs, 0)
			vals[i] = utils.PolyEval(v, xs[i], p)
		}
		interpolated := Curve.Modmul(ls[0], vals[0], p)
		for i := 1; i < len(v); i++ {
			interpolated = interpolated.Plus(Curve.Modmul(ls[i], vals[i], p))
		}
		interpolated.Mod(p)
		assert.Zero(t, Curve.Comp(v[0], interpolated))
	}
}
