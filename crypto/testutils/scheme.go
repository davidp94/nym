// scheme.go - Shared test functions for Coconut implementations
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

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func setupWrapper(cw *coconutworker.CoconutWorker, q int) (coconut.SchemeParams, error) {
	if cw == nil {
		return coconut.Setup(q)
	}
	return cw.Setup(q)
}

// nolint: lll
func keygenWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams) (*coconut.SecretKey, *coconut.VerificationKey, error) {
	if cw == nil {
		return coconut.Keygen(params.(*coconut.Params))
	}
	return cw.Keygen(params.(*coconutworker.MuxParams))
}

// nolint: lll
func ttpKeygenWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, t int, n int) ([]*coconut.SecretKey, []*coconut.VerificationKey, error) {
	if cw == nil {
		return coconut.TTPKeygen(params.(*coconut.Params), t, n)
	}
	return cw.TTPKeygen(params.(*coconutworker.MuxParams), t, n)

}

// nolint: lll
func signWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, sk *coconut.SecretKey, pubM []*Curve.BIG) (*coconut.Signature, error) {
	if cw == nil {
		return coconut.Sign(params.(*coconut.Params), sk, pubM)
	}
	return cw.Sign(params.(*coconutworker.MuxParams), sk, pubM)
}

// nolint: lll
func verifyWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, vk *coconut.VerificationKey, pubM []*Curve.BIG, sig *coconut.Signature) bool {
	if cw == nil {
		return coconut.Verify(params.(*coconut.Params), vk, pubM, sig)
	}
	return cw.Verify(params.(*coconutworker.MuxParams), vk, pubM, sig)
}

// nolint: lll
func randomizeWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, sig *coconut.Signature) *coconut.Signature {
	if cw == nil {
		return coconut.Randomize(params.(*coconut.Params), sig)
	}
	return cw.Randomize(params.(*coconutworker.MuxParams), sig)
}

// nolint: lll
func aggregateSignaturesWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, sigs []*coconut.Signature, pp *coconut.PolynomialPoints) *coconut.Signature {
	if cw == nil {
		return coconut.AggregateSignatures(params.(*coconut.Params), sigs, pp)

	}
	return cw.AggregateSignatures(params.(*coconutworker.MuxParams), sigs, pp)
}

// nolint: lll
func aggregateVerificationKeysWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, vks []*coconut.VerificationKey, pp *coconut.PolynomialPoints) *coconut.VerificationKey {
	if cw == nil {
		return coconut.AggregateVerificationKeys(params.(*coconut.Params), vks, pp)
	}
	return cw.AggregateVerificationKeys(params.(*coconutworker.MuxParams), vks, pp)
}

// nolint: lll
func elGamalKeygenWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams) (*elgamal.PrivateKey, *elgamal.PublicKey) {
	if cw == nil {
		return elgamal.Keygen(params.(*coconut.Params).G)
	}
	return cw.ElGamalKeygen(params.(*coconutworker.MuxParams))
}

// nolint: lll
func prepareBlindSignWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, egPub *elgamal.PublicKey, pubM []*Curve.BIG, privM []*Curve.BIG) (*coconut.BlindSignMats, error) {
	if cw == nil {
		return coconut.PrepareBlindSign(params.(*coconut.Params), egPub, pubM, privM)
	}
	return cw.PrepareBlindSign(params.(*coconutworker.MuxParams), egPub, pubM, privM)
}

// nolint: lll
func unblindWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, blindedSignature *coconut.BlindedSignature, egPriv *elgamal.PrivateKey) *coconut.Signature {
	if cw == nil {
		return coconut.Unblind(params.(*coconut.Params), blindedSignature, egPriv)
	}
	return cw.Unblind(params.(*coconutworker.MuxParams), blindedSignature, egPriv)
}

// nolint: lll
func showBlindSignatureWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, vk *coconut.VerificationKey, sig *coconut.Signature, privM []*Curve.BIG) (*coconut.BlindShowMats, error) {
	if cw == nil {
		return coconut.ShowBlindSignature(params.(*coconut.Params), vk, sig, privM)
	}
	return cw.ShowBlindSignature(params.(*coconutworker.MuxParams), vk, sig, privM)
}

// nolint: lll
func blindSignWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, sk *coconut.SecretKey, blindSignMats *coconut.BlindSignMats, egPub *elgamal.PublicKey, pubM []*Curve.BIG) (*coconut.BlindedSignature, error) {
	if cw == nil {
		return coconut.BlindSign(params.(*coconut.Params), sk, blindSignMats, egPub, pubM)
	}
	return cw.BlindSign(params.(*coconutworker.MuxParams), sk, blindSignMats, egPub, pubM)
}

// nolint: lll
func blindVerifyWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, vk *coconut.VerificationKey, sig *coconut.Signature, showMats *coconut.BlindShowMats, pubM []*Curve.BIG) bool {
	if cw == nil {
		return coconut.BlindVerify(params.(*coconut.Params), vk, sig, showMats, pubM)
	}
	return cw.BlindVerify(params.(*coconutworker.MuxParams), vk, sig, showMats, pubM)

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

// TestKeygenProperties checks basic properties of the Coconut keys, such as whether X = g2^x.
// nolint: lll
func TestKeygenProperties(t *testing.T, params coconut.SchemeParams, sk *coconut.SecretKey, vk *coconut.VerificationKey) {
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

// nolint: gocyclo
func interpolateRandomSubsetOfKeys(p *Curve.BIG, k int, n int, keys interface{}) []interface{} {
	indices := RandomInts(k, n)
	indicesBIG := make([]*Curve.BIG, k)
	for i, val := range indices {
		indicesBIG[i] = Curve.NewBIGint(val)
	}
	li := utils.GenerateLagrangianCoefficients(k, p, indicesBIG, 0)

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
		}

		for i := range polys {
			polysRet[i] = polys[i]
		}
		return polysRet
	}
	return nil // never reached anyway, but compiler complained (even with return in default case)
}

// TestTTPKeygenProperties checks whether any 2 subsets of keys when multiplied by appropriate lagrange basis
// converge to the same values
// nolint: lll
func TestTTPKeygenProperties(t *testing.T, params coconut.SchemeParams, sks []*coconut.SecretKey, vks []*coconut.VerificationKey, k int, n int) {
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

// TestSign verifies whether a coconut signature was correctly constructed
func TestSign(t *testing.T, cw *coconutworker.CoconutWorker) {
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
		{q: 3, attrs: []string{"Foo", "Bar"}, err: nil,
			msg: "Sign should allow keys longer than number of attrs"},
	}

	for _, test := range tests {
		params, err := setupWrapper(cw, test.q)
		assert.Nil(t, err)

		sk, _, err := keygenWrapper(cw, params)
		assert.Nil(t, err)

		p := params.P()

		attrsBig := make([]*Curve.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		sig, err := signWrapper(cw, params, sk, attrsBig)
		if test.err == coconut.ErrSignParams {
			assert.Equal(t, coconut.ErrSignParams, err, test.msg)
			continue // everything beyond that point is UB
		}
		assert.Nil(t, err)

		t1 := Curve.NewBIGcopy(sk.X())
		for i := range attrsBig {
			t1 = t1.Plus(Curve.Modmul(attrsBig[i], sk.Y()[i], p))
		}

		sigTest := Curve.G1mul(sig.Sig1(), t1)
		assert.True(t, sigTest.Equals(sig.Sig2()), test.msg)
	}
}

// TestVerify checks whether only a valid coconut signature successfully verifies.
func TestVerify(t *testing.T, cw *coconutworker.CoconutWorker) {
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
		params, err := setupWrapper(cw, len(test.attrs))
		assert.Nil(t, err)

		sk, vk, err := keygenWrapper(cw, params)
		assert.Nil(t, err)

		attrsBig := make([]*Curve.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		sig, err := signWrapper(cw, params, sk, attrsBig)
		assert.Nil(t, err)
		assert.True(t, verifyWrapper(cw, params, vk, attrsBig, sig), test.msg)

		if len(test.maliciousAttrs) > 0 {
			mAttrsBig := make([]*Curve.BIG, len(test.maliciousAttrs))
			for i := range test.maliciousAttrs {
				mAttrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.maliciousAttrs[i])
				assert.Nil(t, err)
			}

			sig2, err := signWrapper(cw, params, sk, mAttrsBig)
			assert.Nil(t, err)
			assert.False(t, verifyWrapper(cw, params, vk, attrsBig, sig2), test.msg)
			assert.False(t, verifyWrapper(cw, params, vk, mAttrsBig, sig), test.msg)

		}
	}
}

// TestRandomize checks if randomizing a signature still produces a valid coconut signature.
func TestRandomize(t *testing.T, cw *coconutworker.CoconutWorker) {
	tests := []struct {
		attrs []string
		msg   string
	}{
		{attrs: []string{"Hello World!"}, msg: "Should verify a randomized signature on single public attribute"},
		{attrs: []string{"Foo", "Bar", "Baz"}, msg: "Should verify a radomized signature on three public attribute"},
	}

	for _, test := range tests {
		params, err := setupWrapper(cw, len(test.attrs))
		assert.Nil(t, err)

		sk, vk, err := keygenWrapper(cw, params)
		assert.Nil(t, err)

		attrsBig := make([]*Curve.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		sig, err := signWrapper(cw, params, sk, attrsBig)
		assert.Nil(t, err)
		randSig := randomizeWrapper(cw, params, sig)
		assert.True(t, verifyWrapper(cw, params, vk, attrsBig, randSig), test.msg)
	}
}

// TestKeyAggregation checks correctness of aggregating single verification key.
// Aggregation of multiple verification keys is implicitly checked in other tests.
func TestKeyAggregation(t *testing.T, cw *coconutworker.CoconutWorker) {
	tests := []struct {
		attrs []string
		pp    *coconut.PolynomialPoints
		msg   string
	}{
		{attrs: []string{"Hello World!"}, pp: nil,
			msg: "Should verify a signature when single set of verification keys is aggregated (single attribute)"},
		{attrs: []string{"Foo", "Bar", "Baz"}, pp: nil,
			msg: "Should verify a signature when single set of verification keys is aggregated (three attributes)"},
		{attrs: []string{"Hello World!"}, pp: coconut.NewPP([]*Curve.BIG{Curve.NewBIGint(1)}),
			msg: "Should verify a signature when single set of verification keys is aggregated (single attribute)"},
		{attrs: []string{"Foo", "Bar", "Baz"}, pp: coconut.NewPP([]*Curve.BIG{Curve.NewBIGint(1)}),
			msg: "Should verify a signature when single set of verification keys is aggregated (three attributes)"},
	}

	for _, test := range tests {
		params, err := setupWrapper(cw, len(test.attrs))
		assert.Nil(t, err)

		sk, vk, err := keygenWrapper(cw, params)
		assert.Nil(t, err)

		attrsBig := make([]*Curve.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		sig, err := signWrapper(cw, params, sk, attrsBig)
		assert.Nil(t, err)

		avk := aggregateVerificationKeysWrapper(cw, params, []*coconut.VerificationKey{vk}, test.pp)
		assert.True(t, verifyWrapper(cw, params, avk, attrsBig, sig), test.msg)

	}
}

// TestAggregateVerification checks whether signatures and verification keys from multiple authorities
// can be correctly aggregated and verified.
// This particular test does not test the threshold property, it is tested in separate test.
func TestAggregateVerification(t *testing.T, cw *coconutworker.CoconutWorker) {
	tests := []struct {
		attrs          []string
		authorities    int
		maliciousAuth  int
		maliciousAttrs []string
		pp             *coconut.PolynomialPoints
		t              int
		msg            string
	}{
		{attrs: []string{"Hello World!"}, authorities: 1, maliciousAuth: 0, maliciousAttrs: []string{}, pp: nil, t: 0,
			msg: "Should verify aggregated signature when only single signature was used for aggregation"},
		{attrs: []string{"Hello World!"}, authorities: 3, maliciousAuth: 0, maliciousAttrs: []string{}, pp: nil, t: 0,
			msg: "Should verify aggregated signature when three signatures were used for aggregation"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 1, maliciousAuth: 0, maliciousAttrs: []string{}, pp: nil, t: 0,
			msg: "Should verify aggregated signature when only single signature was used for aggregation"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 3, maliciousAuth: 0, maliciousAttrs: []string{}, pp: nil, t: 0,
			msg: "Should verify aggregated signature when three signatures were used for aggregation"},
		{attrs: []string{"Hello World!"}, authorities: 1, maliciousAuth: 2,
			maliciousAttrs: []string{"Malicious Hello World!"},
			pp:             nil,
			t:              0,
			msg:            "Should fail to verify aggregated where malicious signatures were introduced"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 3, maliciousAuth: 2,
			maliciousAttrs: []string{"Foo2", "Bar2", "Baz2"},
			pp:             nil,
			t:              0,
			msg:            "Should fail to verify aggregated where malicious signatures were introduced"},

		{attrs: []string{"Hello World!"}, authorities: 1, maliciousAuth: 0,
			maliciousAttrs: []string{},
			pp:             coconut.NewPP([]*Curve.BIG{Curve.NewBIGint(1)}),
			t:              1,
			msg:            "Should verify aggregated signature when only single signature was used for aggregation +threshold"},
		{attrs: []string{"Hello World!"}, authorities: 3, maliciousAuth: 0,
			maliciousAttrs: []string{},
			pp:             coconut.NewPP([]*Curve.BIG{Curve.NewBIGint(1), Curve.NewBIGint(2), Curve.NewBIGint(3)}),
			t:              2,
			msg:            "Should verify aggregated signature when three signatures were used for aggregation +threshold"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 1, maliciousAuth: 0,
			maliciousAttrs: []string{},
			pp:             coconut.NewPP([]*Curve.BIG{Curve.NewBIGint(1)}),
			t:              1,
			msg:            "Should verify aggregated signature when only single signature was used for aggregation +threshold"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 3, maliciousAuth: 0,
			maliciousAttrs: []string{},
			pp:             coconut.NewPP([]*Curve.BIG{Curve.NewBIGint(1), Curve.NewBIGint(2), Curve.NewBIGint(3)}),
			t:              2,
			msg:            "Should verify aggregated signature when three signatures were used for aggregation +threshold"},
	}

	for _, test := range tests {
		params, err := setupWrapper(cw, len(test.attrs))
		assert.Nil(t, err)

		var sks []*coconut.SecretKey
		var vks []*coconut.VerificationKey

		// generate appropriate keys using appropriate method
		if test.pp == nil {
			sks = make([]*coconut.SecretKey, test.authorities)
			vks = make([]*coconut.VerificationKey, test.authorities)
			for i := 0; i < test.authorities; i++ {
				sk, vk, err := keygenWrapper(cw, params)
				assert.Nil(t, err)
				sks[i] = sk
				vks[i] = vk
			}
		} else {
			sks, vks, err = ttpKeygenWrapper(cw, params, test.t, test.authorities)

			assert.Nil(t, err)
		}

		attrsBig := make([]*Curve.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		signatures := make([]*coconut.Signature, test.authorities)
		for i := 0; i < test.authorities; i++ {

			sig, err := signWrapper(cw, params, sks[i], attrsBig)

			signatures[i] = sig
			assert.Nil(t, err)
		}

		aSig := aggregateSignaturesWrapper(cw, params, signatures, test.pp)
		avk := aggregateVerificationKeysWrapper(cw, params, vks, test.pp)
		assert.True(t, verifyWrapper(cw, params, avk, attrsBig, aSig), test.msg)

		if test.maliciousAuth > 0 {
			msks := make([]*coconut.SecretKey, test.maliciousAuth)
			mvks := make([]*coconut.VerificationKey, test.maliciousAuth)
			for i := 0; i < test.maliciousAuth; i++ {
				sk, vk, err := keygenWrapper(cw, params)
				assert.Nil(t, err)
				msks[i] = sk
				mvks[i] = vk
			}

			mAttrsBig := make([]*Curve.BIG, len(test.maliciousAttrs))
			for i := range test.maliciousAttrs {
				mAttrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.maliciousAttrs[i])
				assert.Nil(t, err)
			}

			mSignatures := make([]*coconut.Signature, test.maliciousAuth)
			for i := 0; i < test.maliciousAuth; i++ {
				var sig *coconut.Signature
				if cw == nil {
					sig, err = coconut.Sign(params.(*coconut.Params), msks[i], mAttrsBig)
				} else {
					sig, err = cw.Sign(params.(*coconutworker.MuxParams), msks[i], mAttrsBig)
				}
				mSignatures[i] = sig
				assert.Nil(t, err)
			}

			maSig := aggregateSignaturesWrapper(cw, params, mSignatures, test.pp)
			mavk := aggregateVerificationKeysWrapper(cw, params, mvks, test.pp)
			maSig2 := aggregateSignaturesWrapper(cw, params, append(signatures, mSignatures...), test.pp)
			mavk2 := aggregateVerificationKeysWrapper(cw, params, append(vks, mvks...), test.pp)

			assert.False(t, verifyWrapper(cw, params, mavk, attrsBig, maSig), test.msg)
			assert.False(t, verifyWrapper(cw, params, mavk2, attrsBig, maSig2), test.msg)

			assert.False(t, verifyWrapper(cw, params, avk, mAttrsBig, maSig), test.msg)
			assert.False(t, verifyWrapper(cw, params, mavk2, mAttrsBig, aSig), test.msg)

			assert.False(t, verifyWrapper(cw, params, avk, mAttrsBig, maSig2), test.msg)
			assert.False(t, verifyWrapper(cw, params, mavk2, mAttrsBig, maSig2), test.msg)
		}
	}
}

// TestBlindVerify checks whether only a valid coconut signature successfully verifies (includes private attributes).
func TestBlindVerify(t *testing.T, cw *coconutworker.CoconutWorker) {
	tests := []struct {
		q    int
		pub  []string
		priv []string
		err  error
		msg  string
	}{
		{q: 2, pub: []string{"Foo", "Bar"}, priv: []string{}, err: coconut.ErrPrepareBlindSignPrivate,
			msg: "Should not allow blindly signing messages with no private attributes"},
		{q: 1, pub: []string{}, priv: []string{"Foo", "Bar"}, err: coconut.ErrPrepareBlindSignParams,
			msg: "Should not allow blindly signing messages with invalid params"},
		{q: 2, pub: []string{}, priv: []string{"Foo", "Bar"}, err: nil,
			msg: "Should blindly sign and verify a valid set of private attributes"},
		{q: 6, pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}, err: nil,
			msg: "Should blindly sign and verify a valid set of public and private attributes"},
		{q: 10, pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}, err: nil,
			msg: "Should blindly sign and verify a valid set of public and private attributes"}, // q > len(pub) + len(priv)
	}

	for _, test := range tests {
		params, err := setupWrapper(cw, test.q)
		assert.Nil(t, err)

		sk, vk, err := keygenWrapper(cw, params)
		assert.Nil(t, err)
		egPriv, egPub := elGamalKeygenWrapper(cw, params)

		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))
		for i := range test.pub {
			pubBig[i], err = utils.HashStringToBig(amcl.SHA256, test.pub[i])
			assert.Nil(t, err)
		}
		for i := range test.priv {
			privBig[i], err = utils.HashStringToBig(amcl.SHA256, test.priv[i])
			assert.Nil(t, err)
		}

		blindSignMats, err := prepareBlindSignWrapper(cw, params, egPub, pubBig, privBig)

		if len(test.priv) == 0 {
			assert.Equal(t, test.err, err)
			continue
		} else if test.q < len(test.priv)+len(test.pub) {
			assert.Equal(t, test.err, err)
			continue
		} else {
			assert.Nil(t, err)
		}

		// ensures len(blindSignMats.enc)+len(public_m) > len(params.hs)
		if test.q <= len(test.priv)+len(test.pub) {
			_, err = blindSignWrapper(cw, params, sk, blindSignMats, egPub, append(pubBig, Curve.NewBIG()))
			assert.Equal(t, coconut.ErrPrepareBlindSignParams, err, test.msg)

			// just to ensure the error is returned; proofs of knowledge are properly tested in their own test file
			_, err = blindSignWrapper(cw, params, sk, blindSignMats, egPub, append(pubBig, Curve.NewBIG()))
			assert.Equal(t, coconut.ErrPrepareBlindSignParams, err, test.msg)
		}

		blindedSignature, err := blindSignWrapper(cw, params, sk, blindSignMats, egPub, pubBig)
		assert.Nil(t, err)

		sig := unblindWrapper(cw, params, blindedSignature, egPriv)

		_, err = showBlindSignatureWrapper(cw, params, vk, sig, []*Curve.BIG{})
		assert.Equal(t, coconut.ErrShowBlindAttr, err, test.msg)

		if len(test.pub) == 0 {
			// ensures len(private_m) > len(vk.beta)
			_, err = showBlindSignatureWrapper(cw, params, vk, sig, append(privBig, Curve.NewBIG()))
			assert.Equal(t, coconut.ErrShowBlindAttr, err, test.msg)
		}

		blindShowMats, err := showBlindSignatureWrapper(cw, params, vk, sig, privBig)
		assert.Nil(t, err)

		assert.True(t, blindVerifyWrapper(cw, params, vk, sig, blindShowMats, pubBig), test.msg)
		// private attributes are revealed
		assert.True(t, verifyWrapper(cw, params, vk, append(privBig, pubBig...), sig), test.msg)

	}
}

// TestThresholdAuthorities checks the threshold property of the appropriate keys, as in whether
// any subset of t verification keys can be used to verify aggregate credential created out of
// any different subset of t issued credentials.
func TestThresholdAuthorities(t *testing.T, cw *coconutworker.CoconutWorker) {
	// for this purpose those randoms don't need to be securely generated
	repeat := 3
	tests := []struct {
		pub  []string
		priv []string
		t    int
		n    int
	}{
		{pub: []string{"foo", "bar"}, priv: []string{"foo2", "bar2"}, t: 1, n: 6},
		{pub: []string{"foo", "bar"}, priv: []string{"foo2", "bar2"}, t: 3, n: 6},
		{pub: []string{"foo", "bar"}, priv: []string{"foo2", "bar2"}, t: 6, n: 6},
		{pub: []string{}, priv: []string{"foo2", "bar2"}, t: 1, n: 6},
		{pub: []string{}, priv: []string{"foo2", "bar2"}, t: 3, n: 6},
		{pub: []string{}, priv: []string{"foo2", "bar2"}, t: 6, n: 6},
	}

	for _, test := range tests {

		params, err := setupWrapper(cw, len(test.pub)+len(test.priv))
		assert.Nil(t, err)

		egPriv, egPub := elGamalKeygenWrapper(cw, params)

		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))

		for i := range test.pub {
			pubBig[i], err = utils.HashStringToBig(amcl.SHA256, test.pub[i])
			assert.Nil(t, err)
		}
		for i := range test.priv {
			privBig[i], err = utils.HashStringToBig(amcl.SHA256, test.priv[i])
			assert.Nil(t, err)
		}

		blindSignMats, err := prepareBlindSignWrapper(cw, params, egPub, pubBig, privBig)
		assert.Nil(t, err)

		sks, vks, err := ttpKeygenWrapper(cw, params, test.t, test.n)
		assert.Nil(t, err)

		// repeat the test repeat number of times to ensure it works with different subsets of keys/sigs
		for a := 0; a < repeat; a++ {
			// choose any t vks
			indices := RandomInts(test.t, test.n)
			vks2 := make([]*coconut.VerificationKey, test.t)
			for i := range vks2 {
				vks2[i] = vks[indices[i]-1]
			}
			// right now each point of vk has value of index + 1
			indices12 := make([]*Curve.BIG, test.t)
			for i, val := range indices {
				indices12[i] = Curve.NewBIGint(val)
			}

			avk := aggregateVerificationKeysWrapper(cw, params, vks2, coconut.NewPP(indices12))

			signatures := make([]*coconut.Signature, test.n)
			for i := 0; i < test.n; i++ {
				blindedSignature, err := blindSignWrapper(cw, params, sks[i], blindSignMats, egPub, pubBig)
				assert.Nil(t, err)
				signatures[i] = unblindWrapper(cw, params, blindedSignature, egPriv)
			}

			// and choose some other subset of t signatures
			indices2 := RandomInts(test.t, test.n)
			sigs2 := make([]*coconut.Signature, test.t)
			for i := range vks2 {
				sigs2[i] = signatures[indices2[i]-1]
			}
			// right now each point of sig has value of index + 1
			indices22 := make([]*Curve.BIG, test.t)
			for i, val := range indices2 {
				indices22[i] = Curve.NewBIGint(val)
			}

			aSig := aggregateSignaturesWrapper(cw, params, sigs2, coconut.NewPP(indices22))
			rSig := randomizeWrapper(cw, params, aSig)

			blindShowMats, err := showBlindSignatureWrapper(cw, params, avk, rSig, privBig)
			assert.Nil(t, err)

			assert.True(t, blindVerifyWrapper(cw, params, avk, rSig, blindShowMats, pubBig))
		}
	}
}
