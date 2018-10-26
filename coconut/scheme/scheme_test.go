// scheme_test.go - tests for Coconut signature scheme
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
package coconut_test

import (
	"testing"

	. "github.com/jstuczyn/CoconutGo/coconut/scheme"
	. "github.com/jstuczyn/CoconutGo/testutils"
	"github.com/stretchr/testify/assert"
)

func TestSchemeSetup(t *testing.T) {
	_, err := Setup(0)
	assert.Equal(t, ErrSetupParams, err, "Should not allow generating params for less than 1 attribute")

	params, err := Setup(10)
	assert.Nil(t, err)
	assert.Len(t, params.Hs(), 10)
}

func TestSchemeKeygen(t *testing.T) {
	params, err := Setup(10)
	assert.Nil(t, err)

	sk, vk, err := Keygen(params)
	assert.Nil(t, err)

	TestKeygenProperties(t, params, sk, vk)
}

func TestSchemeTTPKeygen(t *testing.T) {
	params, err := Setup(10)
	assert.Nil(t, err)

	_, _, err = TTPKeygen(params, 6, 5)
	assert.Equal(t, ErrTTPKeygenParams, err)

	_, _, err = TTPKeygen(params, 0, 6)
	assert.Equal(t, ErrTTPKeygenParams, err)

	tests := []struct {
		t int
		n int
	}{
		{1, 6},
		{3, 6},
		{6, 6},
	}
	for _, test := range tests {
		repeat := 3
		q := 4
		params, _ := Setup(q)

		sks, vks, err := TTPKeygen(params, test.t, test.n)
		assert.Nil(t, err)
		assert.Equal(t, len(sks), len(vks))

		// first check if they work as normal keys
		for i := range sks {
			TestKeygenProperties(t, params, sks[i], vks[i])
		}

		for i := 0; i < repeat; i++ {
			TestTTPKeygenProperties(t, params, sks, vks, test.t, test.n)
		}
	}
}

func TestSchemeSign(t *testing.T) {
	TestSign(t, nil)
}

func TestSchemeVerify(t *testing.T) {
	TestVerify(t, nil)
}

func TestSchemeRandomize(t *testing.T) {
	TestRandomize(t, nil)
}

func TestSchemeKeyAggregation(t *testing.T) {
	TestKeyAggregation(t, nil)
}

// // This particular test does not test the threshold property
func TestSchemeAggregateVerification(t *testing.T) {
	TestAggregateVerification(t, nil)
}

func TestSchemeBlindVerify(t *testing.T) {
	TestBlindVerify(t, nil)
}

// func TestThresholdAuthorities(t *testing.T) {
// 	// for this purpose those randoms don't need to be securely generated
// 	repeat := 3
// 	tests := []struct {
// 		pub  []string
// 		priv []string
// 		t    int
// 		n    int
// 	}{
// 		{pub: []string{"foo", "bar"}, priv: []string{"foo2", "bar2"}, t: 1, n: 6},
// 		{pub: []string{"foo", "bar"}, priv: []string{"foo2", "bar2"}, t: 3, n: 6},
// 		{pub: []string{"foo", "bar"}, priv: []string{"foo2", "bar2"}, t: 6, n: 6},
// 		{pub: []string{}, priv: []string{"foo2", "bar2"}, t: 1, n: 6},
// 		{pub: []string{}, priv: []string{"foo2", "bar2"}, t: 3, n: 6},
// 		{pub: []string{}, priv: []string{"foo2", "bar2"}, t: 6, n: 6},
// 	}

// 	for _, test := range tests {

// 		params, err := Setup(len(test.pub) + len(test.priv))
// 		assert.Nil(t, err)

// 		d, gamma := elgamal.Keygen(params.G)

// 		pubBig := make([]*Curve.BIG, len(test.pub))
// 		privBig := make([]*Curve.BIG, len(test.priv))

// 		for i := range test.pub {
// 			pubBig[i], err = utils.HashStringToBig(amcl.SHA256, test.pub[i])
// 			assert.Nil(t, err)
// 		}
// 		for i := range test.priv {
// 			privBig[i], err = utils.HashStringToBig(amcl.SHA256, test.priv[i])
// 			assert.Nil(t, err)
// 		}

// 		blindSignMats, err := PrepareBlindSign(params, gamma, pubBig, privBig)
// 		assert.Nil(t, err)

// 		sks, vks, err := TTPKeygen(params, test.t, test.n)
// 		assert.Nil(t, err)

// 		// repeat the test repeat number of times to ensure it works with different subsets of keys/sigs
// 		for a := 0; a < repeat; a++ {
// 			// choose any t vks
// 			indices := RandomInts(test.t, test.n)
// 			vks2 := make([]*VerificationKey, test.t)
// 			for i := range vks2 {
// 				vks2[i] = vks[indices[i]-1]
// 			}
// 			// right now each point of vk has value of index + 1
// 			indices12 := make([]*Curve.BIG, test.t)
// 			for i, val := range indices {
// 				indices12[i] = Curve.NewBIGint(val)
// 			}

// 			avk := AggregateVerificationKeys(params, vks2, &PolynomialPoints{indices12})

// 			signatures := make([]*Signature, test.n)
// 			for i := 0; i < test.n; i++ {
// 				blindedSignature, err := BlindSign(params, sks[i], blindSignMats, gamma, pubBig)
// 				assert.Nil(t, err)
// 				signatures[i] = Unblind(params, blindedSignature, d)
// 			}

// 			// and choose some other subset of t signatures
// 			indices2 := RandomInts(test.t, test.n)
// 			sigs2 := make([]*Signature, test.t)
// 			for i := range vks2 {
// 				sigs2[i] = signatures[indices2[i]-1]
// 			}
// 			// right now each point of sig has value of index + 1
// 			indices22 := make([]*Curve.BIG, test.t)
// 			for i, val := range indices2 {
// 				indices22[i] = Curve.NewBIGint(val)
// 			}

// 			aSig := AggregateSignatures(params, sigs2, &PolynomialPoints{indices22})
// 			rSig := Randomize(params, aSig)

// 			blindShowMats, err := ShowBlindSignature(params, avk, rSig, privBig)
// 			assert.Nil(t, err)

// 			assert.True(t, BlindVerify(params, avk, rSig, blindShowMats, pubBig))
// 		}
// 	}
// }

// func BenchmarkSetup(b *testing.B) {
// 	qs := []int{1, 3, 5, 10, 20}
// 	for _, q := range qs {
// 		b.Run(fmt.Sprintf("q=%d", q), func(b *testing.B) {
// 			for i := 0; i < b.N; i++ {
// 				_, err := Setup(q)
// 				if err != nil {
// 					panic(err)
// 				}
// 			}
// 		})
// 	}
// }

// func BenchmarkKeygen(b *testing.B) {
// 	qs := []int{1, 3, 5, 10}
// 	for _, q := range qs {
// 		b.Run(fmt.Sprintf("q=%d", q), func(b *testing.B) {
// 			for i := 0; i < b.N; i++ {
// 				b.StopTimer()
// 				params, _ := Setup(q)
// 				b.StartTimer()
// 				_, _, err := Keygen(params)
// 				if err != nil {
// 					panic(err)
// 				}
// 			}
// 		})
// 	}
// }

// func BenchmarkTTPKeygen(b *testing.B) {
// 	qs := []int{1, 3, 5, 10}
// 	ts := []int{1, 3, 5}
// 	ns := []int{1, 3, 5, 10}
// 	for _, q := range qs {
// 		for _, t := range ts {
// 			for _, n := range ns {
// 				if n < t {
// 					continue
// 				}
// 				b.Run(fmt.Sprintf("q=%d/t=%d/n=%d", q, t, n), func(b *testing.B) {
// 					for i := 0; i < b.N; i++ {
// 						b.StopTimer()
// 						params, _ := Setup(q)
// 						b.StartTimer()
// 						_, _, err := TTPKeygen(params, t, n)
// 						if err != nil {
// 							panic(err)
// 						}
// 					}
// 				})
// 			}
// 		}
// 	}
// }

// func BenchmarkSign(b *testing.B) {
// 	qs := []int{1, 3, 5, 10}
// 	for _, q := range qs {
// 		b.Run(fmt.Sprintf("q=%d", q), func(b *testing.B) {
// 			for i := 0; i < b.N; i++ {
// 				b.StopTimer()
// 				params, _ := Setup(q)
// 				p, rng := params.p, params.G.Rng()
// 				pubs := make([]*Curve.BIG, q) // generate random attributes to sign
// 				for i := range pubs {
// 					pubs[i] = Curve.Randomnum(p, rng)
// 				}
// 				sk, _, _ := Keygen(params)
// 				b.StartTimer()
// 				_, err := Sign(params, sk, pubs)
// 				if err != nil {
// 					panic(err)
// 				}
// 			}
// 		})
// 	}
// }

// func BenchmarkPrepareBlindSign(b *testing.B) {
// 	privns := []int{1, 3, 5, 10}
// 	pubns := []int{1, 3, 5, 10}
// 	for _, privn := range privns {
// 		for _, pubn := range pubns {
// 			b.Run(fmt.Sprintf("pubM=%d/privM=%d", pubn, privn), func(b *testing.B) {
// 				for i := 0; i < b.N; i++ {
// 					b.StopTimer()
// 					params, _ := Setup(pubn + privn)
// 					p, rng := params.p, params.G.Rng()
// 					privs := make([]*Curve.BIG, privn) // generate random attributes to sign
// 					pubs := make([]*Curve.BIG, pubn)   // generate random attributes to sign

// 					for i := range privs {
// 						privs[i] = Curve.Randomnum(p, rng)
// 					}

// 					for i := range pubs {
// 						pubs[i] = Curve.Randomnum(p, rng)
// 					}

// 					_, gamma := elgamal.Keygen(params.G)
// 					b.StartTimer()
// 					_, err := PrepareBlindSign(params, gamma, pubs, privs)
// 					if err != nil {
// 						panic(err)
// 					}
// 				}
// 			})
// 		}
// 	}
// }

// func BenchmarkBlindSign(b *testing.B) {
// 	privns := []int{1, 3, 5, 10}
// 	pubns := []int{1, 3, 5, 10}
// 	for _, privn := range privns {
// 		for _, pubn := range pubns {
// 			b.Run(fmt.Sprintf("pubM=%d/privM=%d", pubn, privn), func(b *testing.B) {
// 				for i := 0; i < b.N; i++ {
// 					b.StopTimer()
// 					params, _ := Setup(pubn + privn)
// 					p, rng := params.p, params.G.Rng()

// 					privs := make([]*Curve.BIG, privn) // generate random attributes to sign
// 					pubs := make([]*Curve.BIG, pubn)   // generate random attributes to sign

// 					for i := range privs {
// 						privs[i] = Curve.Randomnum(p, rng)
// 					}

// 					for i := range pubs {
// 						pubs[i] = Curve.Randomnum(p, rng)
// 					}

// 					_, gamma := elgamal.Keygen(params.G)
// 					blindSignMats, _ := PrepareBlindSign(params, gamma, pubs, privs)

// 					sk, _, _ := Keygen(params)
// 					b.StartTimer()
// 					_, err := BlindSign(params, sk, blindSignMats, gamma, pubs)
// 					if err != nil {
// 						panic(err)
// 					}
// 				}
// 			})
// 		}
// 	}
// }

// var unblindRes *Signature

// // since unblind takes constant time in relation to number of attributes,
// // there is no point in embedding variable number of them into a credential
// func BenchmarkUnblind(b *testing.B) {
// 	var sig *Signature
// 	for i := 0; i < b.N; i++ {
// 		b.StopTimer()
// 		params, _ := Setup(1)
// 		p, rng := params.p, params.G.Rng()

// 		privs := []*Curve.BIG{Curve.Randomnum(p, rng)}
// 		pubs := []*Curve.BIG{}

// 		d, gamma := elgamal.Keygen(params.G)
// 		blindSignMats, _ := PrepareBlindSign(params, gamma, pubs, privs)

// 		sk, _, _ := Keygen(params)
// 		blindSig, _ := BlindSign(params, sk, blindSignMats, gamma, pubs)
// 		b.StartTimer()
// 		sig = Unblind(params, blindSig, d)
// 	}
// 	// it is recommended to store results in package level variables,
// 	// so that compiler would not try to optimize the benchmark
// 	unblindRes = sig
// }

// func BenchmarkVerify(b *testing.B) {
// 	qs := []int{1, 3, 5, 10}
// 	for _, q := range qs {
// 		b.Run(fmt.Sprintf("q=%d", q), func(b *testing.B) {
// 			for i := 0; i < b.N; i++ {
// 				b.StopTimer()
// 				params, _ := Setup(q)
// 				p, rng := params.p, params.G.Rng()
// 				pubs := make([]*Curve.BIG, q) // generate random attributes to sign
// 				for i := range pubs {
// 					pubs[i] = Curve.Randomnum(p, rng)
// 				}
// 				sk, vk, _ := Keygen(params)
// 				sig, _ := Sign(params, sk, pubs)
// 				b.StartTimer()
// 				isValid := Verify(params, vk, pubs, sig)
// 				if !isValid {
// 					panic(isValid)
// 				}
// 			}
// 		})
// 	}
// }

// func BenchmarkShowBlindSignature(b *testing.B) {
// 	privns := []int{1, 3, 5, 10}
// 	for _, privn := range privns {
// 		b.Run(fmt.Sprintf("privM=%d", privn), func(b *testing.B) {
// 			for i := 0; i < b.N; i++ {
// 				b.StopTimer()
// 				params, _ := Setup(privn)
// 				p, rng := params.p, params.G.Rng()

// 				privs := make([]*Curve.BIG, privn) // generate random attributes to sign
// 				pubs := []*Curve.BIG{}

// 				for i := range privs {
// 					privs[i] = Curve.Randomnum(p, rng)
// 				}

// 				d, gamma := elgamal.Keygen(params.G)
// 				blindSignMats, _ := PrepareBlindSign(params, gamma, pubs, privs)

// 				sk, vk, _ := Keygen(params)
// 				blindSig, _ := BlindSign(params, sk, blindSignMats, gamma, pubs)
// 				sig := Unblind(params, blindSig, d)
// 				b.StartTimer()
// 				_, err := ShowBlindSignature(params, vk, sig, privs)
// 				if err != nil {
// 					panic(err)
// 				}
// 			}
// 		})
// 	}
// }

// func BenchmarkBlindVerify(b *testing.B) {
// 	pubns := []int{1, 3, 5, 10}
// 	for _, pubn := range pubns {
// 		b.Run(fmt.Sprintf("pubM=%d", pubn), func(b *testing.B) {
// 			for i := 0; i < b.N; i++ {
// 				b.StopTimer()
// 				params, _ := Setup(pubn + 1)
// 				p, rng := params.p, params.G.Rng()

// 				privs := []*Curve.BIG{Curve.Randomnum(p, rng)}
// 				pubs := make([]*Curve.BIG, pubn)

// 				for i := range pubs {
// 					pubs[i] = Curve.Randomnum(p, rng)
// 				}

// 				d, gamma := elgamal.Keygen(params.G)
// 				blindSignMats, _ := PrepareBlindSign(params, gamma, pubs, privs)

// 				sk, vk, _ := Keygen(params)
// 				blindSig, _ := BlindSign(params, sk, blindSignMats, gamma, pubs)
// 				sig := Unblind(params, blindSig, d)
// 				blindShowMats, _ := ShowBlindSignature(params, vk, sig, privs)

// 				b.StartTimer()
// 				isValid := BlindVerify(params, vk, sig, blindShowMats, pubs)
// 				if !isValid {
// 					panic(isValid)
// 				}
// 			}
// 		})
// 	}
// }

// func Example() {
// 	q := 5                                // number of attributes
// 	privM := []string{"Foo", "Bar", "42"} // private attributes
// 	pubM := []string{"Baz", "43"}         // public attributes

// 	// hash all of the attributes to BIG num:
// 	privMBig := make([]*Curve.BIG, len(privM))
// 	pubMBig := make([]*Curve.BIG, len(pubM))
// 	for i := range privM {
// 		privMBig[i], _ = utils.HashStringToBig(amcl.SHA256, privM[i])
// 	}
// 	for i := range pubM {
// 		pubMBig[i], _ = utils.HashStringToBig(amcl.SHA256, pubM[i])
// 	}

// 	t := 2 // threshold parameter
// 	n := 3 // number of authorities

// 	params, _ := Setup(q)
// 	d, gamma := elgamal.Keygen(params.G) // El-Gamal keypair

// 	// Generate commitment and encryption
// 	blindSignMats, _ := PrepareBlindSign(params, gamma, pubMBig, privMBig)

// 	// Generate keys for all authorities
// 	sks, vks, _ := TTPKeygen(params, t, n)

// 	// Blindly Sign attributes by each authoritiy
// 	blindSignatures := make([]*BlindedSignature, n)
// 	for i := range blindSignatures {
// 		blindSignatures[i], _ = BlindSign(params, sks[i], blindSignMats, gamma, pubMBig)
// 	}

// 	// Unblind all signatures
// 	signatures := make([]*Signature, n)
// 	for i := range blindSignatures {
// 		signatures[i] = Unblind(params, blindSignatures[i], d)
// 	}

// 	// Simple slice of indices
// 	pp1 := &PolynomialPoints{[]*Curve.BIG{Curve.NewBIGint(1), Curve.NewBIGint(2)}}
// 	pp2 := &PolynomialPoints{[]*Curve.BIG{Curve.NewBIGint(2), Curve.NewBIGint(3)}}

// 	// Aggregate any subset of t verification keys
// 	avk1 := AggregateVerificationKeys(params, vks[1:], pp2)
// 	avk2 := AggregateVerificationKeys(params, vks[:len(vks)-1], pp1)

// 	// Aggregate any subset of t credentials
// 	aSig1 := AggregateSignatures(params, signatures[1:], pp2)
// 	aSig2 := AggregateSignatures(params, signatures[:len(signatures)-1], pp1)

// 	// Randomize the credentials
// 	rSig1 := Randomize(params, aSig1)
// 	rSig2 := Randomize(params, aSig2)

// 	// Generate kappas and proofs of corectness
// 	blindShowMats1, _ := ShowBlindSignature(params, avk1, rSig1, privMBig)
// 	blindShowMats2, _ := ShowBlindSignature(params, avk2, rSig2, privMBig)
// 	blindShowMats3, _ := ShowBlindSignature(params, avk1, rSig2, privMBig)
// 	blindShowMats4, _ := ShowBlindSignature(params, avk2, rSig1, privMBig)

// 	// Verify credentials
// 	fmt.Println(BlindVerify(params, avk1, rSig1, blindShowMats1, pubMBig))
// 	fmt.Println(BlindVerify(params, avk2, rSig2, blindShowMats2, pubMBig))
// 	fmt.Println(BlindVerify(params, avk1, rSig2, blindShowMats3, pubMBig))
// 	fmt.Println(BlindVerify(params, avk2, rSig1, blindShowMats4, pubMBig))
// }
