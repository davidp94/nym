// auxiliary.go - tests for auxiliary coconut functions
// Copyright (C) 2018-2019  Jedrzej Stuczynski.
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
package coconut_test

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func TestECPSliceConversion(t *testing.T) {
	bpG := bpgroup.New()
	p, G1, rng := bpG.Order(), bpG.Gen1(), bpG.Rng()

	slices := [][]*Curve.ECP{
		nil,
		{},
		{Curve.G1mul(G1, Curve.Randomnum(p, rng))},
		{Curve.G1mul(G1, Curve.Randomnum(p, rng)), Curve.G1mul(G1, Curve.Randomnum(p, rng))},
		{Curve.G1mul(G1, Curve.Randomnum(p, rng)),
			Curve.G1mul(G1, Curve.Randomnum(p, rng)),
			Curve.G1mul(G1, Curve.Randomnum(p, rng)),
		},
	}

	for _, s := range slices {
		b := coconut.ECPSliceToCompressedBytes(s)
		sr := coconut.CompressedBytesToECPSlice(b)

		for i := range sr {
			assert.NotNil(t, sr[i])
			assert.True(t, sr[i].Equals(s[i]))
		}
	}
}

func TestBIGSliceConversion(t *testing.T) {
	bpG := bpgroup.New()
	p, rng := bpG.Order(), bpG.Rng()

	slices := [][]*Curve.BIG{
		{},
		{Curve.Randomnum(p, rng)},
		{Curve.Randomnum(p, rng), Curve.Randomnum(p, rng)},
		{Curve.Randomnum(p, rng), Curve.Randomnum(p, rng), Curve.Randomnum(p, rng)},
	}

	for _, s := range slices {
		bs, err := coconut.BigSliceToByteSlices(s)
		assert.Len(t, s, len(bs))
		assert.Nil(t, err)

		sr, err := coconut.BigSliceFromByteSlices(bs)
		assert.Nil(t, err)
		for i := range sr {
			assert.NotNil(t, sr[i])
			assert.Zero(t, Curve.Comp(sr[i], s[i]))
		}
	}
}
