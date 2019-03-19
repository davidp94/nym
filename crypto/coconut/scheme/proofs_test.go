// proofs_test.go - tests for NIZK
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
	"fmt"
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/constants"

	. "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	. "0xacab.org/jstuczyn/CoconutGo/crypto/testutils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

//
// TESTS
//

func TestSchemeSignerProof(t *testing.T) {
	TestSignerProof(t, nil)
}

func TestSchemeVerifierProof(t *testing.T) {
	TestVerifierProof(t, nil)
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
				g1, p, rng := params.G1(), params.P(), params.G.Rng()
				privs := make([]*Curve.BIG, privn) // generate random attributes to sign

				for i := range privs {
					privs[i] = Curve.Randomnum(p, rng)
				}

				r := Curve.Randomnum(p, rng)
				cm := Curve.G1mul(g1, r)
				for i := range privs {
					cm.Add(Curve.G1mul(params.Hs()[i], privs[i]))
				}

				cmb := make([]byte, constants.ECPLen)
				cm.ToBytes(cmb, true)

				h, _ := utils.HashBytesToG1(amcl.SHA512, cmb)

				_, egPub := elgamal.Keygen(params.G)

				encs := make([]*elgamal.Encryption, privn)
				ks := make([]*Curve.BIG, privn)
				for i := range privs {
					c, k := elgamal.Encrypt(params.G, egPub, privs[i], h)
					encs[i] = c
					ks[i] = k
				}

				b.StartTimer()
				_, err := ConstructSignerProof(params, egPub.Gamma(), encs, cm, ks, r, []*Curve.BIG{}, privs)
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
				g1, p, rng := params.G1(), params.P(), params.G.Rng()
				privs := make([]*Curve.BIG, privn) // generate random attributes to sign

				for i := range privs {
					privs[i] = Curve.Randomnum(p, rng)
				}

				r := Curve.Randomnum(p, rng)
				cm := Curve.G1mul(g1, r)
				for i := range privs {
					cm.Add(Curve.G1mul(params.Hs()[i], privs[i]))
				}

				cmb := make([]byte, constants.ECPLen)
				cm.ToBytes(cmb, true)

				h, _ := utils.HashBytesToG1(amcl.SHA512, cmb)

				_, egPub := elgamal.Keygen(params.G)

				encs := make([]*elgamal.Encryption, privn)
				ks := make([]*Curve.BIG, privn)
				for i := range privs {
					c, k := elgamal.Encrypt(params.G, egPub, privs[i], h)
					encs[i] = c
					ks[i] = k
				}

				signerProof, _ := ConstructSignerProof(params, egPub.Gamma(), encs, cm, ks, r, []*Curve.BIG{}, privs)
				lambda := NewLambda(cm, encs, signerProof)
				b.StartTimer()
				isValid := VerifySignerProof(params, egPub.Gamma(), lambda)
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
				p, rng := params.P(), params.G.Rng()
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
				verifierProof, _ = ConstructVerifierProof(params, vk, sig, privs, t)
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
				p, rng := params.P(), params.G.Rng()
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
