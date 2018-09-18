package coconut

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

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
		{pub: []string{"Foo"}, priv: []string{"Foo2"}, msg: "The proof should verify on single public and private attributes"},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}, msg: "The proof should verify on three public and private attributes"},
	}

	for _, test := range tests {
		params, err := Setup(len(test.pub) + len(test.priv))
		assert.Nil(t, err)

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

		attributes := append(privBig, pubBig...)

		r := BLS381.Randomnum(params.G.Ord, params.G.Rng)
		cm := BLS381.G1mul(params.G.Gen1, r)
		for i := range attributes {
			cm.Add(BLS381.G1mul(params.hs[i], attributes[i]))
		}
		h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
		assert.Nil(t, err)

		_, gamma := elgamal.Keygen(params.G)
		encs := make([]*elgamal.ElGamalEncryption, len(test.priv))
		ks := make([]*BLS381.BIG, len(test.priv))
		for i := range test.priv {
			c, k := elgamal.Encrypt(params.G, gamma, privBig[i], h)
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

		_, err = ConstructSignerProof(&Params{G: params.G, hs: params.hs[1:]}, gamma, encs, cm, ks, r, pubBig, privBig)
		assert.Equal(t, ErrConstructSignerAttrs, err)

		_, err = ConstructSignerProof(params, gamma, encs, cm, ks, r, append(pubBig, BLS381.NewBIG()), privBig)
		assert.Equal(t, ErrConstructSignerAttrs, err)

		signerProof, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, pubBig, privBig)
		assert.Nil(t, err)

		if len(test.priv) > 0 {
			assert.False(t, VerifySignerProof(params, gamma, encs[1:], cm, signerProof), test.msg)
			assert.False(t, VerifySignerProof(params, gamma, encs, cm, &SignerProof{c: signerProof.c, rr: signerProof.rr, rk: signerProof.rk[1:], rm: signerProof.rm}), test.msg)
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
		{pub: []string{"Foo"}, priv: []string{"Foo2"}, msg: "The proof should verify on single public and private attributes"},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}, msg: "The proof should verify on three public and private attributes"},
	}

	for _, test := range tests {
		params, err := Setup(len(test.pub) + len(test.priv))
		assert.Nil(t, err)

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

		sk, vk, err := Keygen(params)
		assert.Nil(t, err)
		d, gamma := elgamal.Keygen(params.G)

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

func TestVerifyVerifierProofMultiplePrivate(t *testing.T) {
	params, err := Setup(3)
	assert.Nil(t, err)

	sk, vk, err := Keygen(params)
	assert.Nil(t, err)
	d, gamma := elgamal.Keygen(params.G)

	priv := []string{"Foo2", "Bar2", "Baz2"}
	pubBig := []*BLS381.BIG{}
	privBig := make([]*BLS381.BIG, len(priv))

	for i := range priv {
		privBig[i], err = utils.HashStringToBig(amcl.SHA256, priv[i])
		if err != nil {
			t.Error(err)
		}
	}

	blindSignMats, err := PrepareBlindSign(params, gamma, pubBig, privBig)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := BlindSign(params, sk, blindSignMats, gamma, pubBig)
	if err != nil {
		t.Error(err)
	}

	sig := Unblind(params, blindedSignature, d)

	blindShowMats, err := ShowBlindSignature(params, vk, sig, privBig)
	if err != nil {
		t.Error(err)
	}

	if !VerifyVerifierProof(params, vk, sig, blindShowMats) {
		t.Error("The verifier proof is invalid for three private attribute (no public)")
	}
}

func TestVerifyVerifierProofMultipleMixed(t *testing.T) {
	params, err := Setup(6)
	assert.Nil(t, err)

	sk, vk, err := Keygen(params)
	assert.Nil(t, err)
	d, gamma := elgamal.Keygen(params.G)

	pub := []string{"Foo", "Bar", "Baz"}
	priv := []string{"Foo2", "Bar2", "Baz2"}

	pubBig := make([]*BLS381.BIG, len(pub))
	privBig := make([]*BLS381.BIG, len(priv))
	for i := range pub {
		pubBig[i], err = utils.HashStringToBig(amcl.SHA256, pub[i])
		if err != nil {
			t.Error(err)
		}
	}
	for i := range priv {
		privBig[i], err = utils.HashStringToBig(amcl.SHA256, priv[i])
		if err != nil {
			t.Error(err)
		}
	}

	blindSignMats, err := PrepareBlindSign(params, gamma, pubBig, privBig)
	if err != nil {
		t.Error(err)
	}

	blindedSignature, err := BlindSign(params, sk, blindSignMats, gamma, pubBig)
	if err != nil {
		t.Error(err)
	}

	sig := Unblind(params, blindedSignature, d)

	blindShowMats, err := ShowBlindSignature(params, vk, sig, privBig)
	if err != nil {
		t.Error(err)
	}

	if !VerifyVerifierProof(params, vk, sig, blindShowMats) {
		t.Error("The verifier proof is invalid for three public and three private attribute")
	}
}
