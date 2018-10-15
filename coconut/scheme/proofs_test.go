// proofs_test.go - tests for NIZK
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
package coconut

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

//
// TESTS
//

func TestSignerProof(t *testing.T) {
	tests := []struct {
		pub  []string
		priv []string
		msg  string
	}{
		{pub: []string{}, priv: []string{"Foo2"}, msg: "The proof should verify on single private attribute"},
		{pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"}, msg: "The proof should verify on three private attributes"},
		{pub: []string{"Foo"}, priv: []string{}, msg: "The proof should verify on single public attribute"},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{}, msg: "The proof should verify on three public attribute"},
		{pub: []string{"Foo"}, priv: []string{"Foo2"},
			msg: "The proof should verify on single public and private attributes"},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"},
			msg: "The proof should verify on three public and private attributes"},
	}

	for _, test := range tests {
		params, err := Setup(len(test.pub) + len(test.priv))
		assert.Nil(t, err)
		G, p, g1, rng := params.G, params.p, params.g1, params.G.Rng()

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

		attributes := append(privBig, pubBig...)

		r := Curve.Randomnum(p, rng)
		cm := Curve.G1mul(g1, r)
		for i := range attributes {
			cm.Add(Curve.G1mul(params.hs[i], attributes[i]))
		}

		b := make([]byte, utils.MB+1)
		cm.ToBytes(b, true)

		h, err := utils.HashBytesToG1(amcl.SHA512, b)
		assert.Nil(t, err)

		_, gamma := elgamal.Keygen(G)
		encs := make([]*elgamal.Encryption, len(test.priv))
		ks := make([]*Curve.BIG, len(test.priv))
		for i := range test.priv {
			c, k := elgamal.Encrypt(G, gamma, privBig[i], h)
			encs[i] = c
			ks[i] = k
		}

		if len(test.priv) > 0 {
			_, err = ConstructSignerProof(params, gamma, encs, cm, ks[1:], r, pubBig, privBig)
			assert.Equal(t, ErrConstructSignerCiphertexts, err)

			_, err = ConstructSignerProof(params, gamma, encs[1:], cm, ks, r, pubBig, privBig)
			assert.Equal(t, ErrConstructSignerCiphertexts, err)

			_, err = ConstructSignerProof(params, gamma, encs, cm, ks, r, pubBig, privBig[1:])
			assert.Equal(t, ErrConstructSignerCiphertexts, err)
		}

		_, err = ConstructSignerProof(&Params{G: G, hs: params.hs[1:]}, gamma, encs, cm, ks, r, pubBig, privBig)
		assert.Equal(t, ErrConstructSignerAttrs, err)

		_, err = ConstructSignerProof(params, gamma, encs, cm, ks, r, append(pubBig, Curve.NewBIG()), privBig)
		assert.Equal(t, ErrConstructSignerAttrs, err)

		signerProof, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, pubBig, privBig)
		assert.Nil(t, err)

		if len(test.priv) > 0 {
			assert.False(t, VerifySignerProof(params, gamma, encs[1:], cm, signerProof), test.msg)
			assert.False(t, VerifySignerProof(params, gamma, encs, cm,
				&SignerProof{c: signerProof.c, rr: signerProof.rr, rk: signerProof.rk[1:], rm: signerProof.rm}), test.msg)
		}
		assert.True(t, VerifySignerProof(params, gamma, encs, cm, signerProof), test.msg)
	}
}

func TestVerifierProof(t *testing.T) {
	tests := []struct {
		pub  []string
		priv []string
		msg  string
	}{
		{pub: []string{}, priv: []string{"Foo2"}, msg: "The proof should verify on single private attribute"},
		{pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"}, msg: "The proof should verify on three private attributes"},
		{pub: []string{"Foo"}, priv: []string{"Foo2"},
			msg: "The proof should verify on single public and private attributes"},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"},
			msg: "The proof should verify on three public and private attributes"},
	}

	for _, test := range tests {
		params, err := Setup(len(test.pub) + len(test.priv))
		assert.Nil(t, err)
		G := params.G

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

		sk, vk, err := Keygen(params)
		assert.Nil(t, err)
		d, gamma := elgamal.Keygen(G)

		blindSignMats, err := PrepareBlindSign(params, gamma, pubBig, privBig)
		assert.Nil(t, err)

		blindedSignature, err := BlindSign(params, sk, blindSignMats, gamma, pubBig)
		assert.Nil(t, err)

		sig := Unblind(params, blindedSignature, d)

		blindShowMats, err := ShowBlindSignature(params, vk, sig, privBig)
		assert.Nil(t, err)

		assert.True(t, VerifyVerifierProof(params, vk, sig, blindShowMats), test.msg)
	}
}

//
// BENCHMARKS
//

func BenchmarkConstructSignerProof(b *testing.B) {
	// public attributes have negligible effect on performance of that function,
	// so only variable number of private attributes is being tested
	privns := []int{1, 3, 5, 10}
	for _, privn := range privns {
		b.Run(fmt.Sprintf("priv=%d", privn), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				params, _ := Setup(privn)
				g1, p, rng := params.g1, params.p, params.G.Rng()
				privs := make([]*Curve.BIG, privn) // generate random attributes to sign

				for i := range privs {
					privs[i] = Curve.Randomnum(p, rng)
				}

				r := Curve.Randomnum(p, rng)
				cm := Curve.G1mul(g1, r)
				for i := range privs {
					cm.Add(Curve.G1mul(params.hs[i], privs[i]))
				}

				cmb := make([]byte, utils.MB+1)
				cm.ToBytes(cmb, true)

				h, _ := utils.HashBytesToG1(amcl.SHA512, cmb)

				_, gamma := elgamal.Keygen(params.G)

				encs := make([]*elgamal.Encryption, privn)
				ks := make([]*Curve.BIG, privn)
				for i := range privs {
					c, k := elgamal.Encrypt(params.G, gamma, privs[i], h)
					encs[i] = c
					ks[i] = k
				}

				b.StartTimer()
				_, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, []*Curve.BIG{}, privs)
				if err != nil {
					panic(err)
				}
			}
		})
	}
}

func BenchmarkVerifySignerProof(b *testing.B) {
	privns := []int{1, 3, 5, 10}
	for _, privn := range privns {
		b.Run(fmt.Sprintf("priv=%d", privn), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				params, _ := Setup(privn)
				g1, p, rng := params.g1, params.p, params.G.Rng()
				privs := make([]*Curve.BIG, privn) // generate random attributes to sign

				for i := range privs {
					privs[i] = Curve.Randomnum(p, rng)
				}

				r := Curve.Randomnum(p, rng)
				cm := Curve.G1mul(g1, r)
				for i := range privs {
					cm.Add(Curve.G1mul(params.hs[i], privs[i]))
				}

				cmb := make([]byte, utils.MB+1)
				cm.ToBytes(cmb, true)

				h, _ := utils.HashBytesToG1(amcl.SHA512, cmb)

				_, gamma := elgamal.Keygen(params.G)

				encs := make([]*elgamal.Encryption, privn)
				ks := make([]*Curve.BIG, privn)
				for i := range privs {
					c, k := elgamal.Encrypt(params.G, gamma, privs[i], h)
					encs[i] = c
					ks[i] = k
				}

				signerProof, _ := ConstructSignerProof(params, gamma, encs, cm, ks, r, []*Curve.BIG{}, privs)
				b.StartTimer()
				isValid := VerifySignerProof(params, gamma, encs, cm, signerProof)
				if !isValid {
					panic(isValid)
				}

			}
		})
	}
}

var verifierProofRes *VerifierProof

func BenchmarkConstructVerifierProof(b *testing.B) {
	privns := []int{1, 3, 5, 10}
	var verifierProof *VerifierProof
	for _, privn := range privns {
		b.Run(fmt.Sprintf("priv=%d", privn), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				params, _ := Setup(privn)
				p, rng := params.p, params.G.Rng()
				privs := make([]*Curve.BIG, privn) // generate random attributes to sign
				pubs := []*Curve.BIG{}

				for i := range privs {
					privs[i] = Curve.Randomnum(p, rng)
				}

				d, gamma := elgamal.Keygen(params.G)
				blindSignMats, _ := PrepareBlindSign(params, gamma, pubs, privs)

				sk, vk, _ := Keygen(params)
				blindSig, _ := BlindSign(params, sk, blindSignMats, gamma, pubs)
				sig := Unblind(params, blindSig, d)

				t := Curve.Randomnum(p, rng)
				b.StartTimer()
				verifierProof = ConstructVerifierProof(params, vk, sig, privs, t)
			}
		})
	}
	// it is recommended to store results in package level variables,
	// so that compiler would not try to optimize the benchmark
	verifierProofRes = verifierProof
}

func BenchmarkVerifyVerifierProof(b *testing.B) {
	privns := []int{1, 3, 5, 10}
	for _, privn := range privns {
		b.Run(fmt.Sprintf("priv=%d", privn), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				params, _ := Setup(privn)
				p, rng := params.p, params.G.Rng()
				privs := make([]*Curve.BIG, privn) // generate random attributes to sign
				pubs := []*Curve.BIG{}

				for i := range privs {
					privs[i] = Curve.Randomnum(p, rng)
				}

				d, gamma := elgamal.Keygen(params.G)
				blindSignMats, _ := PrepareBlindSign(params, gamma, pubs, privs)

				sk, vk, _ := Keygen(params)
				blindSig, _ := BlindSign(params, sk, blindSignMats, gamma, pubs)
				sig := Unblind(params, blindSig, d)
				blindShowMats, _ := ShowBlindSignature(params, vk, sig, privs)
				b.StartTimer()
				isValid := VerifyVerifierProof(params, vk, sig, blindShowMats)
				if !isValid {
					panic(isValid)
				}
			}
		})
	}
}
