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
package utils

import (
	"encoding/hex"
	"math/rand"
	"testing"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/constants"

	"github.com/stretchr/testify/assert"

	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

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
		comp := Curve.Comp(test.expected, PolyEval(test.coeff, test.x, test.o))
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
			ls[i] = LagrangeBasis(i, p, xs, 0)
			vals[i] = PolyEval(v, xs[i], p)
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
	hash1, err1 := HashBytes(amcl.SHA256, b)
	hash2, err2 := HashBytes(amcl.SHA384, b)
	hash3, err3 := HashBytes(amcl.SHA512, b)
	hash4, err4 := HashBytes(42, b)
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
		g2Hex := "061a10bb519eb62feb8d8c7e8c61edb6a4648bbb4898bf0d91ee4224c803fb2b05" +
			"16aaf9ba737833310aa78c5982aa5b1f4d746bae3784b70d8c34c1e7d54cf30218" +
			"97a06baf93439a90e096698c822329bd0ae6bdbe09bd19f0e07891cd2b9a0ebb2b" +
			"0e7c8b15268f6d4456f5f38d37b09006ffd739c9578a2d1aec6b3ace9b"

		assert.Equal(t, ordHex, ToCoconutString(G.Order()))
		assert.Equal(t, g1Hex, ToCoconutString(G.Gen1()))
		assert.Equal(t, g2Hex, ToCoconutString(G.Gen2()))
	}

	// check that you can correctly recover random ones
	r := Curve.Randomnum(G.Order(), G.Rng())
	g1r := Curve.G1mul(G.Gen1(), r)
	g2r := Curve.G2mul(G.Gen2(), r)

	rHex := ToCoconutString(r)
	g1rHex := ToCoconutString(g1r)
	g2rHex := ToCoconutString(g2r)

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
	assert.Empty(t, ToCoconutString(f))
}

func randomString(n int) string {
	var letter = []rune(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")

	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

func TestHashToBIG(t *testing.T) {
	shas := []int{amcl.SHA256, amcl.SHA384, amcl.SHA512, 42} // invalid sha value added at the end
	m1 := "Hello World!"
	m2 := randomString(64)

	for _, sha := range shas {
		for _, m := range []string{m1, m2} {
			// ensure the wrapper gives out same result as underlying function
			r1, err1 := HashStringToBig(sha, m)
			r2, err2 := HashBytesToBig(sha, []byte(m))
			hash, _ := HashBytes(sha, []byte(m))
			if sha != amcl.SHA256 && sha != amcl.SHA384 && sha != amcl.SHA512 {
				assert.Nil(t, r1)
				assert.Nil(t, r2)
				assert.NotNil(t, err1)
				assert.NotNil(t, err2)
			} else if Curve.CURVE_PAIRING_TYPE == Curve.BN && sha != amcl.SHA256 {
				assert.Nil(t, r1)
				assert.Nil(t, r2)
				assert.NotNil(t, err1)
				assert.NotNil(t, err2)
			} else {
				assert.Zero(t, Curve.Comp(r1, r2))
				assert.Nil(t, err1)
				assert.Nil(t, err2)
			}
			if r1 != nil {
				// for BN curve, the value might be larger than ord as mod is not taken
				if Curve.CURVE_PAIRING_TYPE == Curve.BN {
					b := make([]byte, constants.BIGLen)
					r1.ToBytes(b)
					assert.Equal(t, b, hash)
				} else {
					q := Curve.NewBIGints(Curve.CURVE_Order)
					hash = addHashPadding(sha, hash)
					y := Curve.FromBytes(hash)
					y.Mod(q)
					assert.Zero(t, Curve.Comp(y, r1))
				}
			}
		}
	}
}

func TestHashToG1(t *testing.T) {
	shas := []int{amcl.SHA256, amcl.SHA384, amcl.SHA512, 42} // invalid sha value added at the end
	m1 := "Hello World!"
	m2 := randomString(64)
	for _, sha := range shas {
		for _, m := range []string{m1, m2} {
			// ensure the wrapper gives out same result as underlying function
			r1, err1 := HashStringToG1(sha, m)
			r2, err2 := HashBytesToG1(sha, []byte(m))
			hash, _ := HashBytes(sha, []byte(m))
			if sha != amcl.SHA256 && sha != amcl.SHA384 && sha != amcl.SHA512 {
				assert.Nil(t, r1)
				assert.Nil(t, r2)
				assert.NotNil(t, err1)
				assert.NotNil(t, err2)
			} else if Curve.CURVE_PAIRING_TYPE == Curve.BN && sha != amcl.SHA512 {
				assert.Nil(t, r1)
				assert.Nil(t, r2)
				assert.NotNil(t, err1)
				assert.NotNil(t, err2)
			} else {
				assert.True(t, r1.Equals(r2))
				assert.Nil(t, err1)
				assert.Nil(t, err2)
			}
			// that test case is so specific so that once the specs change
			// I'd remember to update the code due to failing test since results
			// would start to diverge
			if r1 != nil && Curve.CURVE_PAIRING_TYPE == Curve.BN {
				p := Curve.NewBIGints(Curve.Modulus)
				x := Curve.FromBytes(hash)
				E := Curve.NewECPbigint(x, 1)
				for E.Is_infinity() {
					hash, _ = HashBytes(sha, hash)
					x := Curve.FromBytes(hash)
					x.Mod(p)
					E = Curve.NewECPbigint(x, 1)
				}
				assert.True(t, r1.Equals(E))
			}
		}
	}
}
