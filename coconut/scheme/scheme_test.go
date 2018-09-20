package coconut

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

func TestSchemeSetup(t *testing.T) {
	_, err := Setup(0)
	assert.Equal(t, ErrSetupParams, err, "Should not allow generating params for less than 1 attribute")

	params, err := Setup(10)
	assert.Nil(t, err)
	assert.Equal(t, 10, len(params.hs))
}

func keygenTest(t *testing.T, params *Params, sk *SecretKey, vk *VerificationKey) {
	assert.True(t, params.G.Gen2.Equals(vk.g2))
	assert.True(t, BLS381.G2mul(vk.g2, sk.x).Equals(vk.alpha))
	assert.Equal(t, len(sk.y), len(vk.beta))
	for i := range vk.beta {
		assert.Equal(t, vk.beta[i], BLS381.G2mul(vk.g2, sk.y[i]))
	}
}

func TestSchemeKeygen(t *testing.T) {
	params, err := Setup(10)
	assert.Nil(t, err)

	sk, vk, err := Keygen(&Params{G: params.G, hs: nil})
	assert.Equal(t, ErrKeygenParams, err, "Should not allow generating params for less than 1 attribute")

	sk, vk, err = Keygen(params)
	assert.Nil(t, err)

	keygenTest(t, params, sk, vk)
}

func TestSchemeTTPKeygen(t *testing.T) {
	params, err := Setup(10)
	assert.Nil(t, err)

	_, _, err = TTPKeygen(params, 6, 5)
	assert.Equal(t, ErrTTPKeygenParams, err)

	_, _, err = TTPKeygen(params, 0, 6)
	assert.Equal(t, ErrTTPKeygenParams, err)

	_, _, err = TTPKeygen(&Params{G: params.G, hs: nil}, 6, 6)
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
			keygenTest(t, params, sks[i], vks[i])
		}

		// choose random 2 subsets of t keys and ensure that when multiplied by langrage basis they converge to same value
		for i := 0; i < repeat; i++ {
			//
			// sks
			//

			indices1 := randomInts(test.t, test.n)
			sks21 := make([]*SecretKey, test.t)
			for i := range sks21 {
				sks21[i] = sks[indices1[i]-1]
			}
			// right now each point of sk has value of index + 1
			indices12 := make([]*BLS381.BIG, test.t)
			l11 := make([]*BLS381.BIG, test.t)
			for i, val := range indices1 {
				indices12[i] = BLS381.NewBIGint(val)
			}
			for i := 0; i < test.t; i++ {
				l11[i] = utils.LagrangeBasis(i, params.G.Ord, indices12, 0)
			}

			// we can do it for all polynomials used for x and ys
			polys1 := make([]*BLS381.BIG, q+1)
			// initialise
			for i := range polys1 {
				polys1[i] = BLS381.NewBIG()
			}
			for i := range polys1 {
				for j := range sks21 {
					if i == 0 { // x
						polys1[i] = polys1[i].Plus(BLS381.Modmul(l11[j], sks21[j].x, params.G.Ord))
					} else { // ys
						polys1[i] = polys1[i].Plus(BLS381.Modmul(l11[j], sks21[j].y[i-1], params.G.Ord))
					}
				}
			}
			for i := range polys1 {
				polys1[i].Mod(params.G.Ord)
			}

			indices2 := randomInts(test.t, test.n)
			sks22 := make([]*SecretKey, test.t)
			for i := range sks22 {
				sks22[i] = sks[indices2[i]-1]
			}
			indices22 := make([]*BLS381.BIG, test.t)
			l12 := make([]*BLS381.BIG, test.t)
			for i, val := range indices2 {
				indices22[i] = BLS381.NewBIGint(val)
			}
			for i := 0; i < test.t; i++ {
				l12[i] = utils.LagrangeBasis(i, params.G.Ord, indices22, 0)
			}

			polys2 := make([]*BLS381.BIG, q+1)
			for i := range polys2 {
				polys2[i] = BLS381.NewBIG()
			}
			for i := range polys2 {
				for j := range sks22 {
					if i == 0 { // x
						polys2[i] = polys2[i].Plus(BLS381.Modmul(l12[j], sks22[j].x, params.G.Ord))
					} else { // ys
						polys2[i] = polys2[i].Plus(BLS381.Modmul(l12[j], sks22[j].y[i-1], params.G.Ord))
					}
				}
			}
			for i := range polys2 {
				polys2[i].Mod(params.G.Ord)
				assert.Zero(t, BLS381.Comp(polys1[i], polys2[i]))
			}

			// repeat the same procedure for vks (can't easily reuse code due to different types)
			//
			// vks
			//
			indices1 = randomInts(test.t, test.n)
			vks21 := make([]*VerificationKey, test.t)
			for i := range sks21 {
				vks21[i] = vks[indices1[i]-1]
			}
			// right now each point of sk has value of index + 1
			indices12 = make([]*BLS381.BIG, test.t)
			l11 = make([]*BLS381.BIG, test.t)
			for i, val := range indices1 {
				indices12[i] = BLS381.NewBIGint(val)
			}
			for i := 0; i < test.t; i++ {
				l11[i] = utils.LagrangeBasis(i, params.G.Ord, indices12, 0)
			}

			// we can do it for all polynomials used for alpha and betas
			polys1v := make([]*BLS381.ECP2, q+1)
			// initialise
			for i := range polys1v {
				polys1v[i] = BLS381.NewECP2()
			}
			for i := range polys1v {
				for j := range vks21 {
					if i == 0 { // alpha
						polys1v[i].Add(BLS381.G2mul(vks21[j].alpha, l11[j]))
					} else { // beta
						polys1v[i].Add(BLS381.G2mul(vks21[j].beta[i-1], l11[j]))
					}
				}
			}

			indices2 = randomInts(test.t, test.n)
			vks22 := make([]*VerificationKey, test.t)
			for i := range sks22 {
				vks22[i] = vks[indices2[i]-1]
			}
			indices22 = make([]*BLS381.BIG, test.t)
			l12 = make([]*BLS381.BIG, test.t)
			for i, val := range indices2 {
				indices22[i] = BLS381.NewBIGint(val)
			}
			for i := 0; i < test.t; i++ {
				l12[i] = utils.LagrangeBasis(i, params.G.Ord, indices22, 0)
			}

			polys2v := make([]*BLS381.ECP2, q+1)
			for i := range polys2v {
				polys2v[i] = BLS381.NewECP2()
			}
			for i := range polys2v {
				for j := range vks22 {
					if i == 0 { // alpha
						polys2v[i].Add(BLS381.G2mul(vks22[j].alpha, l12[j]))
					} else { // beta
						polys2v[i].Add(BLS381.G2mul(vks22[j].beta[i-1], l12[j]))
					}
				}
			}
			for i := range polys2v {
				assert.True(t, polys1v[i].Equals(polys2v[i]))
			}
		}
	}
}

func TestSchemeSign(t *testing.T) {
	tests := []struct {
		q     int
		attrs []string
		err   error
		msg   string
	}{
		{q: 1, attrs: []string{"Hello World!"}, err: nil, msg: "For single attribute sig2 should be equal to (x + m * y) * sig1"},
		{q: 3, attrs: []string{"Foo", "Bar", "Baz"}, err: nil, msg: "For three attributes sig2 shguld be equal to (x + m1 * y1 + m2 * y2 + m3 * y3) * sig1"},
		{q: 2, attrs: []string{"Foo", "Bar", "Baz"}, err: ErrSignParams, msg: "Sign should fail due to invalid param combination"},
		{q: 3, attrs: []string{"Foo", "Bar"}, err: ErrSignParams, msg: "Sign should fail due to invalid param combination"},
	}

	for _, test := range tests {
		params, err := Setup(test.q)
		assert.Nil(t, err)

		G := params.G
		sk, _, err := Keygen(params)
		assert.Nil(t, err)

		attrsBig := make([]*BLS381.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		sig, err := Sign(params, sk, attrsBig)
		if test.err == ErrSignParams {
			assert.Equal(t, ErrSignParams, err, test.msg)
			return // everything beyond that point is UB
		}
		assert.Nil(t, err)

		t1 := BLS381.NewBIGcopy(sk.x)
		for i := range sk.y {
			t1 = t1.Plus(BLS381.Modmul(attrsBig[i], sk.y[i], G.Ord))
		}

		sigTest := BLS381.G1mul(sig.sig1, t1)
		assert.True(t, sigTest.Equals(sig.sig2), test.msg)
	}
}

func TestSchemeVerify(t *testing.T) {
	tests := []struct {
		attrs          []string
		maliciousAttrs []string
		msg            string
	}{
		{attrs: []string{"Hello World!"}, maliciousAttrs: []string{}, msg: "Should verify a valid signature on single public attribute"},
		{attrs: []string{"Foo", "Bar", "Baz"}, maliciousAttrs: []string{}, msg: "Should verify a valid signature on mulitple public attribute"},
		{attrs: []string{"Hello World!"}, maliciousAttrs: []string{"Malicious Hello World!"}, msg: "Should not verify a signature when malicious attribute is introduced"},
		{attrs: []string{"Foo", "Bar", "Baz"}, maliciousAttrs: []string{"Foo2", "Bar2", "Baz2"}, msg: "Should not verify a signature when malicious attributes are introduced"},
	}

	for _, test := range tests {
		params, err := Setup(len(test.attrs))
		assert.Nil(t, err)

		sk, vk, err := Keygen(params)
		assert.Nil(t, err)

		attrsBig := make([]*BLS381.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}
		sig, err := Sign(params, sk, attrsBig)
		assert.Nil(t, err)
		assert.True(t, Verify(params, vk, attrsBig, sig), test.msg)

		if len(test.maliciousAttrs) > 0 {
			mAttrsBig := make([]*BLS381.BIG, len(test.maliciousAttrs))
			for i := range test.maliciousAttrs {
				mAttrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.maliciousAttrs[i])
				assert.Nil(t, err)
			}
			sig2, err := Sign(params, sk, mAttrsBig)
			assert.Nil(t, err)

			assert.False(t, Verify(params, vk, attrsBig, sig2), test.msg)
			assert.False(t, Verify(params, vk, mAttrsBig, sig), test.msg)
		}
	}
}

// todo: add tests for private
func TestSchemeRandomize(t *testing.T) {
	tests := []struct {
		attrs []string
		msg   string
	}{
		{attrs: []string{"Hello World!"}, msg: "Should verify a randomized signature on single public attribute"},
		{attrs: []string{"Foo", "Bar", "Baz"}, msg: "Should verify a radomized signature on three public attribute"},
	}

	for _, test := range tests {
		params, err := Setup(len(test.attrs))
		assert.Nil(t, err)

		sk, vk, err := Keygen(params)
		assert.Nil(t, err)

		attrsBig := make([]*BLS381.BIG, len(test.attrs))
		for i := range test.attrs {
			var err error
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}
		sig, err := Sign(params, sk, attrsBig)
		assert.Nil(t, err)

		randSig := Randomize(params, sig)
		assert.True(t, Verify(params, vk, attrsBig, randSig), test.msg)
	}
}

func TestSchemeKeyAggregation(t *testing.T) {
	tests := []struct {
		attrs []string
		pp    *PolynomialPoints
		msg   string
	}{
		{attrs: []string{"Hello World!"}, pp: nil, msg: "Should verify a signature when single set of verification keys is aggregated (single attribute)"},
		{attrs: []string{"Foo", "Bar", "Baz"}, pp: nil, msg: "Should verify a signature when single set of verification keys is aggregated (three attributes)"},
		{attrs: []string{"Hello World!"}, pp: &PolynomialPoints{[]*BLS381.BIG{BLS381.NewBIGint(1)}}, msg: "Should verify a signature when single set of verification keys is aggregated (single attribute)"},
		{attrs: []string{"Foo", "Bar", "Baz"}, pp: &PolynomialPoints{[]*BLS381.BIG{BLS381.NewBIGint(1)}}, msg: "Should verify a signature when single set of verification keys is aggregated (three attributes)"},
	}

	for _, test := range tests {
		params, err := Setup(len(test.attrs))
		assert.Nil(t, err)

		sk, vk, err := Keygen(params)
		assert.Nil(t, err)

		attrsBig := make([]*BLS381.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		sig, err := Sign(params, sk, attrsBig)
		assert.Nil(t, err)

		avk := AggregateVerificationKeys(params, []*VerificationKey{vk}, test.pp)
		assert.True(t, Verify(params, avk, attrsBig, sig), test.msg)
	}
}

// This particular test does not test the threshold property
func TestSchemeAggregateVerification(t *testing.T) {
	tests := []struct {
		attrs          []string
		authorities    int
		maliciousAuth  int
		maliciousAttrs []string
		pp             *PolynomialPoints
		t              int
		msg            string
	}{
		{attrs: []string{"Hello World!"}, authorities: 1, maliciousAuth: 0, maliciousAttrs: []string{}, pp: nil, t: 0, msg: "Should verify aggregated signature when only single signature was used for aggregation"},
		{attrs: []string{"Hello World!"}, authorities: 3, maliciousAuth: 0, maliciousAttrs: []string{}, pp: nil, t: 0, msg: "Should verify aggregated signature when three signatures were used for aggregation"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 1, maliciousAuth: 0, maliciousAttrs: []string{}, pp: nil, t: 0, msg: "Should verify aggregated signature when only single signature was used for aggregation"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 3, maliciousAuth: 0, maliciousAttrs: []string{}, pp: nil, t: 0, msg: "Should verify aggregated signature when three signatures were used for aggregation"},
		{attrs: []string{"Hello World!"}, authorities: 1, maliciousAuth: 2, maliciousAttrs: []string{"Malicious Hello World!"}, pp: nil, t: 0, msg: "Should fail to verify aggregated where malicious signatures were introduced"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 3, maliciousAuth: 2, maliciousAttrs: []string{"Foo2", "Bar2", "Baz2"}, pp: nil, t: 0, msg: "Should fail to verify aggregated where malicious signatures were introduced"},

		{attrs: []string{"Hello World!"}, authorities: 1, maliciousAuth: 0, maliciousAttrs: []string{}, pp: &PolynomialPoints{[]*BLS381.BIG{BLS381.NewBIGint(1)}}, t: 1, msg: "Should verify aggregated signature when only single signature was used for aggregation (threshold)"},
		{attrs: []string{"Hello World!"}, authorities: 3, maliciousAuth: 0, maliciousAttrs: []string{}, pp: &PolynomialPoints{[]*BLS381.BIG{BLS381.NewBIGint(1), BLS381.NewBIGint(2), BLS381.NewBIGint(3)}}, t: 2, msg: "Should verify aggregated signature when three signatures were used for aggregation (threshold)"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 1, maliciousAuth: 0, maliciousAttrs: []string{}, pp: &PolynomialPoints{[]*BLS381.BIG{BLS381.NewBIGint(1)}}, t: 1, msg: "Should verify aggregated signature when only single signature was used for aggregation (threshold)"},
		{attrs: []string{"Foo", "Bar", "Baz"}, authorities: 3, maliciousAuth: 0, maliciousAttrs: []string{}, pp: &PolynomialPoints{[]*BLS381.BIG{BLS381.NewBIGint(1), BLS381.NewBIGint(2), BLS381.NewBIGint(3)}}, t: 2, msg: "Should verify aggregated signature when three signatures were used for aggregation (threshold)"},
	}

	for _, test := range tests {
		params, err := Setup(len(test.attrs))
		assert.Nil(t, err)

		var sks []*SecretKey
		var vks []*VerificationKey

		if test.pp == nil {
			sks = make([]*SecretKey, test.authorities)
			vks = make([]*VerificationKey, test.authorities)
			for i := 0; i < test.authorities; i++ {
				sk, vk, err := Keygen(params)
				assert.Nil(t, err)
				sks[i] = sk
				vks[i] = vk
			}
		} else {
			sks, vks, err = TTPKeygen(params, test.t, test.authorities)
			assert.Nil(t, err)
		}

		attrsBig := make([]*BLS381.BIG, len(test.attrs))
		for i := range test.attrs {
			attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.attrs[i])
			assert.Nil(t, err)
		}

		signatures := make([]*Signature, test.authorities)
		for i := 0; i < test.authorities; i++ {
			signatures[i], err = Sign(params, sks[i], attrsBig)
			assert.Nil(t, err)
		}

		aSig := AggregateSignatures(params, signatures, test.pp)
		avk := AggregateVerificationKeys(params, vks, test.pp)

		assert.True(t, Verify(params, avk, attrsBig, aSig), test.msg)

		if test.maliciousAuth > 0 {
			msks := make([]*SecretKey, test.maliciousAuth)
			mvks := make([]*VerificationKey, test.maliciousAuth)
			for i := 0; i < test.maliciousAuth; i++ {
				sk, vk, err := Keygen(params)
				assert.Nil(t, err)
				msks[i] = sk
				mvks[i] = vk
			}

			mAttrsBig := make([]*BLS381.BIG, len(test.maliciousAttrs))
			for i := range test.maliciousAttrs {
				mAttrsBig[i], err = utils.HashStringToBig(amcl.SHA256, test.maliciousAttrs[i])
				assert.Nil(t, err)
			}

			mSignatures := make([]*Signature, test.maliciousAuth)
			for i := 0; i < test.maliciousAuth; i++ {
				mSignatures[i], err = Sign(params, msks[i], mAttrsBig)
				assert.Nil(t, err)
			}

			maSig := AggregateSignatures(params, mSignatures, test.pp)
			mavk := AggregateVerificationKeys(params, mvks, test.pp)
			// todo: think of some way to test it if malicious authorities are present?
			maSig2 := AggregateSignatures(params, append(signatures, mSignatures...), test.pp)
			mavk2 := AggregateVerificationKeys(params, append(vks, mvks...), test.pp)

			assert.False(t, Verify(params, mavk, attrsBig, maSig), test.msg)
			assert.False(t, Verify(params, mavk2, attrsBig, maSig2), test.msg)

			assert.False(t, Verify(params, avk, mAttrsBig, maSig), test.msg)
			assert.False(t, Verify(params, mavk2, mAttrsBig, aSig), test.msg)

			assert.False(t, Verify(params, avk, mAttrsBig, maSig2), test.msg)
			assert.False(t, Verify(params, mavk2, mAttrsBig, maSig2), test.msg)
		}
	}
}

func TestSchemeBlindVerify(t *testing.T) {
	tests := []struct {
		q    int
		pub  []string
		priv []string
		err  error
		msg  string
	}{
		{q: 2, pub: []string{"Foo", "Bar"}, priv: []string{}, err: ErrPrepareBlindSignPrivate, msg: "Should not allow blindly signing messages with no private attributes"},
		{q: 1, pub: []string{}, priv: []string{"Foo", "Bar"}, err: ErrPrepareBlindSignParams, msg: "Should not allow blindly signing messages with invalid params"},
		{q: 2, pub: []string{}, priv: []string{"Foo", "Bar"}, err: nil, msg: "Should blindly sign a valid set of private attributes"},
		{q: 6, pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}, err: nil, msg: "Should blindly sign a valid set of public and private attributes"},
		{q: 10, pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}, err: nil, msg: "Should blindly sign a valid set of public and private attributes"}, // q > len(pub) + len(priv)
	}

	for _, test := range tests {
		params, err := Setup(test.q)
		assert.Nil(t, err)

		sk, vk, err := Keygen(params)
		assert.Nil(t, err)
		d, gamma := elgamal.Keygen(params.G)

		pubBig := make([]*BLS381.BIG, len(test.pub))
		privBig := make([]*BLS381.BIG, len(test.priv))

		for i := range test.pub {
			pubBig[i], err = utils.HashStringToBig(amcl.SHA256, test.pub[i])
			assert.Nil(t, err)
		}
		for i := range test.priv {
			privBig[i], err = utils.HashStringToBig(amcl.SHA256, test.priv[i])
			assert.Nil(t, err)
		}

		blindSignMats, err := PrepareBlindSign(params, gamma, pubBig, privBig)
		if len(test.priv) == 0 {
			assert.Equal(t, test.err, err)
			return
		} else if test.q < len(test.priv)+len(test.pub) {
			assert.Equal(t, test.err, err)
			return
		} else {
			assert.Nil(t, err)
		}

		_, err = BlindSign(params, sk, blindSignMats, gamma, append(pubBig, BLS381.NewBIG())) // ensures len(blindSignMats.enc)+len(public_m) > len(params.hs)
		assert.Equal(t, ErrPrepareBlindSignParams, err, test.msg)

		incorrectGamma := BLS381.NewECP()
		incorrectGamma.Copy(gamma)
		incorrectGamma.Add(BLS381.NewECP())                                                            // adds point in infinity
		_, err = BlindSign(params, sk, blindSignMats, incorrectGamma, append(pubBig, BLS381.NewBIG())) // just to ensure the error is returned; proofs of knowledge are properly tested in their own test file
		assert.Equal(t, ErrPrepareBlindSignPrivate, err, test.msg)

		blindedSignature, err := BlindSign(params, sk, blindSignMats, gamma, pubBig)
		sig := Unblind(params, blindedSignature, d)

		_, err = ShowBlindSignature(params, vk, sig, []*BLS381.BIG{})
		assert.Equal(t, ErrShowBlindAttr, err, test.msg)

		_, err = ShowBlindSignature(params, vk, sig, append(privBig, BLS381.NewBIG())) // ensures len(private_m) > len(vk.beta
		assert.Equal(t, ErrShowBlindAttr, err, test.msg)

		blindShowMats, err := ShowBlindSignature(params, vk, sig, privBig)
		assert.Nil(t, err)

		assert.True(t, BlindVerify(params, vk, sig, blindShowMats, pubBig), test.msg)
		assert.True(t, Verify(params, vk, append(privBig, pubBig...), sig), test.msg) // private attributes are revealed
	}
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

// returns random (non-repetitive) q ints, > 0, < max
func randomInts(q int, max int) []int {
	ints := make([]int, q)
	seen := []int{}
	for i := range ints {
		r := randomInt(seen, max)
		ints[i] = r
		seen = append(seen, r)
	}
	return ints
}

func TestThresholdAuthorities(t *testing.T) {
	// for this purpose those randoms don't need to be securely generated
	repeat := 3
	rand.Seed(time.Now().UnixNano())
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

		params, err := Setup(len(test.pub) + len(test.priv))
		assert.Nil(t, err)

		d, gamma := elgamal.Keygen(params.G)

		pubBig := make([]*BLS381.BIG, len(test.pub))
		privBig := make([]*BLS381.BIG, len(test.priv))

		for i := range test.pub {
			pubBig[i], err = utils.HashStringToBig(amcl.SHA256, test.pub[i])
			assert.Nil(t, err)
		}
		for i := range test.priv {
			privBig[i], err = utils.HashStringToBig(amcl.SHA256, test.priv[i])
			assert.Nil(t, err)
		}

		blindSignMats, err := PrepareBlindSign(params, gamma, pubBig, privBig)
		assert.Nil(t, err)

		sks, vks, err := TTPKeygen(params, test.t, test.n)
		assert.Nil(t, err)

		// repeat the test repeat number of times to ensure it works with different subsets of keys/sigs
		for a := 0; a < repeat; a++ {
			// choose any t vks
			indices := randomInts(test.t, test.n)
			vks2 := make([]*VerificationKey, test.t)
			for i := range vks2 {
				vks2[i] = vks[indices[i]-1]
			}
			// right now each point of vk has value of index + 1
			indices12 := make([]*BLS381.BIG, test.t)
			for i, val := range indices {
				indices12[i] = BLS381.NewBIGint(val)
			}

			avk := AggregateVerificationKeys(params, vks2, &PolynomialPoints{indices12})

			signatures := make([]*Signature, test.n)
			for i := 0; i < test.n; i++ {
				blindedSignature, err := BlindSign(params, sks[i], blindSignMats, gamma, pubBig)
				assert.Nil(t, err)
				signatures[i] = Unblind(params, blindedSignature, d)
			}

			// and choose some other subset of t signatures
			indices2 := randomInts(test.t, test.n)
			sigs2 := make([]*Signature, test.t)
			for i := range vks2 {
				sigs2[i] = signatures[indices2[i]-1]
			}
			// right now each point of sig has value of index + 1
			indices22 := make([]*BLS381.BIG, test.t)
			for i, val := range indices2 {
				indices22[i] = BLS381.NewBIGint(val)
			}

			aSig := AggregateSignatures(params, sigs2, &PolynomialPoints{indices22})
			rSig := Randomize(params, aSig)

			blindShowMats, err := ShowBlindSignature(params, avk, rSig, privBig)
			assert.Nil(t, err)

			assert.True(t, BlindVerify(params, avk, rSig, blindShowMats, pubBig))
		}
	}
}
