// schemer.go - Shared test functions for Coconut implementations
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

// Package schemetest provides functions used for testing both regular and concurrent coconut scheme.
package schemetest

import (
	"math/rand"
	"testing"
	"time"

	"github.com/jstuczyn/CoconutGo/coconut/concurrency/coconutclientworker"

	"github.com/jstuczyn/CoconutGo/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randomInt(seen []int, max int) int {
	candidate := 1 + rand.Intn(max)
	for _, b := range seen {
		if b == candidate {
			return randomInt(seen, max)
		}
	}
	return candidate
}

// RandomInts returns random (non-repetitive) q ints, > 0, < max
func RandomInts(q int, max int) []int {
	ints := make([]int, q)
	seen := []int{}
	for i := range ints {
		r := randomInt(seen, max)
		ints[i] = r
		seen = append(seen, r)
	}
	return ints
}

// KeygenTest checks basic properties of the Coconut keys, such as whether X = g2^x.
func TestKeygenProperties(t *testing.T, params coconut.CoconutParams, sk *coconut.SecretKey, vk *coconut.VerificationKey) {
	g2p := params.G2()

	assert.True(t, g2p.Equals(vk.G2()))
	assert.True(t, Curve.G2mul(vk.G2(), sk.X()).Equals(vk.Alpha()))
	assert.Equal(t, len(sk.Y()), len(vk.Beta()))

	g2 := vk.G2()
	y := sk.Y()
	beta := vk.Beta()
	for i := range beta {
		assert.Equal(t, beta[i], Curve.G2mul(g2, y[i]))
	}
}

func interpolateRandomSubsetOfKeys(p *Curve.BIG, k int, n int, keys interface{}) []interface{} {
	indices := RandomInts(k, n)
	indicesBIG := make([]*Curve.BIG, k)
	li := make([]*Curve.BIG, k)
	for i, val := range indices {
		indicesBIG[i] = Curve.NewBIGint(val)
	}
	for i := 0; i < k; i++ {
		li[i] = utils.LagrangeBasis(i, p, indicesBIG, 0)
	}
	switch v := keys.(type) {
	case []*coconut.SecretKey:
		keySub := make([]*coconut.SecretKey, k)
		for i := range keySub {
			keySub[i] = v[indices[i]-1]
		}
		q := len(keySub[0].Y())
		polys := make([]*Curve.BIG, q+1)
		polysRet := make([]interface{}, q+1)
		for i := range polys {
			polys[i] = Curve.NewBIG()
		}
		for i := range polys {
			for j := range keySub {
				if i == 0 { // x
					polys[i] = polys[i].Plus(Curve.Modmul(li[j], keySub[j].X(), p))
				} else { // ys
					polys[i] = polys[i].Plus(Curve.Modmul(li[j], keySub[j].Y()[i-1], p))
				}
			}
		}
		for i := range polys {
			polys[i].Mod(p)
			polysRet[i] = polys[i]
		}
		return polysRet

	case []*coconut.VerificationKey:
		keySub := make([]*coconut.VerificationKey, k)
		for i := range keySub {
			keySub[i] = v[indices[i]-1]
		}
		q := len(keySub[0].Beta())
		polys := make([]*Curve.ECP2, q+1)
		polysRet := make([]interface{}, q+1)
		for i := range polys {
			polys[i] = Curve.NewECP2()
		}
		for i := range polys {
			for j := range keySub {
				if i == 0 { // alpha
					polys[i].Add(Curve.G2mul(keySub[j].Alpha(), li[j]))
				} else { // beta
					polys[i].Add(Curve.G2mul(keySub[j].Beta()[i-1], li[j]))
				}
			}
			for i := range polys {
				polysRet[i] = polys[i]
			}
			return polysRet
		}
	}
	return nil // never reached anyway, but compiler complained (even with return in default case)
}

// TestTTPKeygenProperties checks whether any 2 subsets of keys when multiplied by appropriate lagrange basis
// converge to the same values
func TestTTPKeygenProperties(t *testing.T, params coconut.CoconutParams, sks []*coconut.SecretKey, vks []*coconut.VerificationKey, k int, n int) {
	p := params.P()

	polysSk1 := interpolateRandomSubsetOfKeys(p, k, n, sks)
	polysSk2 := interpolateRandomSubsetOfKeys(p, k, n, sks)
	for i := range polysSk1 {
		assert.Zero(t, Curve.Comp(polysSk1[i].(*Curve.BIG), polysSk2[i].(*Curve.BIG)))
	}

	polysVk1 := interpolateRandomSubsetOfKeys(p, k, n, vks)
	polysVk2 := interpolateRandomSubsetOfKeys(p, k, n, vks)
	for i := range polysVk1 {
		assert.True(t, polysVk1[i].(*Curve.ECP2).Equals(polysVk2[i].(*Curve.ECP2)))
	}
}

func setupAndKeygen(t *testing.T, q int, ccw *coconutclientworker.CoconutClientWorker) (coconut.CoconutParams, *coconut.SecretKey, *coconut.VerificationKey) {
	if ccw == nil {
		params, err := coconut.Setup(q)
		assert.Nil(t, err)

		sk, vk, err := coconut.Keygen(params)
		assert.Nil(t, err)
		return params, sk, vk
	}
	params, err := ccw.Setup(q)
	assert.Nil(t, err)

	sk, vk, err := ccw.Keygen(params)
	assert.Nil(t, err)
	return params, sk, vk
}

// TestSign verifies whether a coconut signature was correctly constructed
func TestSign(t *testing.T, ccw *coconutclientworker.CoconutClientWorker) {
	tests := []struct {
		q     int
		attrs []string
		err   error
		msg   string
	}{
		{q: 1, attrs: []string{"Hello World!"}, err: nil,
			msg: "For single attribute sig2 should be equal to (x + m * y) * sig1"},
		{q: 3, attrs: []string{"Foo", "Bar", "Baz"}, err: nil,
			msg: "For three attributes sig2 shguld be equal to (x + m1 * y1 + m2 * y2 + m3 * y3) * sig1"},
		{q: 2, attrs: []string{"Foo", "Bar", "Baz"}, err: coconut.ErrSignParams,
			msg: "Sign should fail due to invalid param combination"},
		{q: 3, attrs: []string{"Foo", "Bar"}, err: coconut.ErrSignParams,
			msg: "Sign should fail due to invalid param combination"},
	}

	for _, test := range tests {
		params, sk, _ := setupAndKeygen(t, test.q, ccw)
		p := params.P()

		attrsBig := make([]*Curve.BIG, len(test.attrs))
		var err error
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		var sig *coconut.Signature
		if ccw == nil {
			sig, err = coconut.Sign(params.(*coconut.Params), sk, attrsBig)
		} else {
			sig, err = ccw.Sign(params.(*coconutclientworker.MuxParams), sk, attrsBig)
		}
		if test.err == coconut.ErrSignParams {
			assert.Equal(t, coconut.ErrSignParams, err, test.msg)
			continue // everything beyond that point is UB
		}
		assert.Nil(t, err)

		t1 := Curve.NewBIGcopy(sk.X())
		for i := range sk.Y() {
			t1 = t1.Plus(Curve.Modmul(attrsBig[i], sk.Y()[i], p))
		}

		sigTest := Curve.G1mul(sig.Sig1(), t1)
		assert.True(t, sigTest.Equals(sig.Sig2()), test.msg)
	}
}

func TestVerify(t *testing.T, ccw *coconutclientworker.CoconutClientWorker) {
	tests := []struct {
		attrs          []string
		maliciousAttrs []string
		msg            string
	}{
		{attrs: []string{"Hello World!"}, maliciousAttrs: []string{},
			msg: "Should verify a valid signature on single public attribute"},
		{attrs: []string{"Foo", "Bar", "Baz"}, maliciousAttrs: []string{},
			msg: "Should verify a valid signature on multiple public attribute"},
		{attrs: []string{"Hello World!"}, maliciousAttrs: []string{"Malicious Hello World!"},
			msg: "Should not verify a signature when malicious attribute is introduced"},
		{attrs: []string{"Foo", "Bar", "Baz"}, maliciousAttrs: []string{"Foo2", "Bar2", "Baz2"},
			msg: "Should not verify a signature when malicious attributes are introduced"},
	}

	for _, test := range tests {
		params, sk, vk := setupAndKeygen(t, len(test.attrs), ccw)

		attrsBig := make([]*Curve.BIG, len(test.attrs))
		var err error
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		var sig *coconut.Signature
		if ccw == nil {
			sig, err = coconut.Sign(params.(*coconut.Params), sk, attrsBig)
			assert.Nil(t, err)
			assert.True(t, coconut.Verify(params.(*coconut.Params), vk, attrsBig, sig), test.msg)
		} else {
			sig, err = ccw.Sign(params.(*coconutclientworker.MuxParams), sk, attrsBig)
			assert.Nil(t, err)
			assert.True(t, ccw.Verify(params.(*coconutclientworker.MuxParams), vk, attrsBig, sig), test.msg)
		}

		if len(test.maliciousAttrs) > 0 {
			mAttrsBig := make([]*Curve.BIG, len(test.maliciousAttrs))
			for i := range test.maliciousAttrs {
				mAttrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.maliciousAttrs[i])
				assert.Nil(t, err)
			}

			var sig2 *coconut.Signature
			if ccw == nil {
				sig2, err = coconut.Sign(params.(*coconut.Params), sk, mAttrsBig)
				assert.False(t, coconut.Verify(params.(*coconut.Params), vk, attrsBig, sig2), test.msg)
				assert.False(t, coconut.Verify(params.(*coconut.Params), vk, mAttrsBig, sig), test.msg)
			} else {
				sig2, err = ccw.Sign(params.(*coconutclientworker.MuxParams), sk, mAttrsBig)
				assert.False(t, ccw.Verify(params.(*coconutclientworker.MuxParams), vk, attrsBig, sig2), test.msg)
				assert.False(t, ccw.Verify(params.(*coconutclientworker.MuxParams), vk, mAttrsBig, sig), test.msg)
			}
		}
	}
}
