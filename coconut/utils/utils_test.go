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
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
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

func TestHashBytes(t *testing.T) {
	b := []byte("Some arbitrary string to convert into bytes")
	hash1, err1 := utils.HashBytes(amcl.SHA256, b)
	hash2, err2 := utils.HashBytes(amcl.SHA384, b)
	hash3, err3 := utils.HashBytes(amcl.SHA512, b)
	hash4, err4 := utils.HashBytes(42, b)
	assert.Nil(t, err1)
	assert.Nil(t, err2)
	assert.Nil(t, err3)
	assert.NotNil(t, err4)
	assert.Len(t, hash1, amcl.SHA256)
	assert.Len(t, hash2, amcl.SHA384)
	assert.Len(t, hash3, amcl.SHA512)
	assert.Len(t, hash4, 0)
}

func TestToCoconutString(t *testing.T) {
	G := bpgroup.New()
	if Curve.CURVE_PAIRING_TYPE == Curve.BN {
		ordHex := "2523648240000001BA344D8000000007FF9F800000000010A10000000000000D"
		g1Hex := "032523648240000001ba344d80000000086121000000000013a700000000000012"
		g2Hex := "061a10bb519eb62feb8d8c7e8c61edb6a4648bbb4898bf0d91ee4224c803fb2b0516aaf9ba737833310aa78c5982aa5b1f4d746bae3784b70d8c34c1e7d54cf3021897a06baf93439a90e096698c822329bd0ae6bdbe09bd19f0e07891cd2b9a0ebb2b0e7c8b15268f6d4456f5f38d37b09006ffd739c9578a2d1aec6b3ace9b"

		assert.Equal(t, ordHex, utils.ToCoconutString(G.Order()))
		assert.Equal(t, g1Hex, utils.ToCoconutString(G.Gen1()))
		assert.Equal(t, g2Hex, utils.ToCoconutString(G.Gen2()))
	}

	// check that you can correctly recover random ones
	r := Curve.Randomnum(G.Order(), G.Rng())
	g1r := Curve.G1mul(G.Gen1(), r)
	g2r := Curve.G2mul(G.Gen2(), r)

	rHex := utils.ToCoconutString(r)
	g1rHex := utils.ToCoconutString(g1r)
	g2rHex := utils.ToCoconutString(g2r)

	b1, err := hex.DecodeString(rHex)
	assert.Nil(t, err)
	assert.Zero(t, Curve.Comp(r, Curve.FromBytes(b1)))

	b2, err := hex.DecodeString(g1rHex)
	assert.Nil(t, err)
	assert.True(t, g1r.Equals(Curve.ECP_fromBytes(b2)))

	b3, err := hex.DecodeString(g2rHex)
	assert.Nil(t, err)
	assert.True(t, g2r.Equals(Curve.ECP2_fromBytes(b3)))

	// another Printable element that is not BIG, ECP or ECP2
	f := Curve.NewFP12int(42)
	assert.Empty(t, utils.ToCoconutString(f))
}
