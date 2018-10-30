package coconut_test

import (
	"testing"

	"github.com/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/CoconutGo/elgamal"

	"github.com/jstuczyn/CoconutGo/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func TestSecretKeyMarshal(t *testing.T) {
	params, _ := coconut.Setup(4)
	sk, _, _ := coconut.Keygen(params)
	data, err := sk.MarshalBinary()
	assert.Nil(t, err)
	recoveredSk := &coconut.SecretKey{}
	assert.Nil(t, recoveredSk.UnmarshalBinary(data))
	assert.Zero(t, Curve.Comp(sk.X(), recoveredSk.X()))
	for i := range sk.Y() {
		assert.Zero(t, Curve.Comp(sk.Y()[i], recoveredSk.Y()[i]))
	}
}

func TestVerificationKeyMarshal(t *testing.T) {
	params, _ := coconut.Setup(4)
	_, vk, _ := coconut.Keygen(params)
	data, err := vk.MarshalBinary()
	assert.Nil(t, err)
	recoveredVk := &coconut.VerificationKey{}
	assert.Nil(t, recoveredVk.UnmarshalBinary(data))
	assert.True(t, vk.G2().Equals(recoveredVk.G2()))
	assert.True(t, vk.Alpha().Equals(recoveredVk.Alpha()))
	for i := range vk.Beta() {
		assert.True(t, vk.Beta()[i].Equals(recoveredVk.Beta()[i]))
	}
}

func TestSignatureMarshal(t *testing.T) {
	params, _ := coconut.Setup(1)
	sk, _, _ := coconut.Keygen(params)
	m := Curve.Randomnum(params.P(), params.G.Rng())
	sig, _ := coconut.Sign(params, sk, []*Curve.BIG{m})
	data, err := sig.MarshalBinary()
	assert.Nil(t, err)
	recoveredSig := &coconut.Signature{}
	assert.Nil(t, recoveredSig.UnmarshalBinary(data))
	assert.True(t, sig.Sig1().Equals(recoveredSig.Sig1()))
	assert.True(t, sig.Sig2().Equals(recoveredSig.Sig2()))
}

func TestBlindedSignatureMarshal(t *testing.T) {
	params, _ := coconut.Setup(4)
	sk, _, _ := coconut.Keygen(params)
	_, gamma := elgamal.Keygen(params.G)

	pubBig := make([]*Curve.BIG, 2)
	privBig := make([]*Curve.BIG, 2)
	for i := range pubBig {
		pubBig[i] = Curve.Randomnum(params.P(), params.G.Rng())
	}
	for i := range privBig {
		privBig[i] = Curve.Randomnum(params.P(), params.G.Rng())
	}

	blindSignMats, _ := coconut.PrepareBlindSign(params, gamma, pubBig, privBig)
	blindedSignature, _ := coconut.BlindSign(params, sk, blindSignMats, gamma, pubBig)

	data, err := blindedSignature.MarshalBinary()
	assert.Nil(t, err)
	recoveredSig := &coconut.BlindedSignature{}
	assert.Nil(t, recoveredSig.UnmarshalBinary(data))
	assert.True(t, blindedSignature.Sig1().Equals(recoveredSig.Sig1()))
	assert.True(t, blindedSignature.Sig2Tilda().C1().Equals(recoveredSig.Sig2Tilda().C1()))
	assert.True(t, blindedSignature.Sig2Tilda().C2().Equals(recoveredSig.Sig2Tilda().C2()))
}

func TestSignerProofMarshal(t *testing.T) {
	tests := []struct {
		pub  []string
		priv []string
	}{
		{pub: []string{}, priv: []string{"Foo2"}},
		// {pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"}},
		// {pub: []string{"Foo"}, priv: []string{}},
		// {pub: []string{"Foo", "Bar", "Baz"}, priv: []string{}},
		// {pub: []string{"Foo"}, priv: []string{"Foo2"}},
		// {pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}},
	}

	for _, test := range tests {
		params, _ := coconut.Setup(len(test.pub) + len(test.priv))

		p, g1, hs, rng := params.P(), params.G1(), params.Hs(), params.G.Rng()

		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))

		for i := range test.pub {
			pubBig[i], _ = utils.HashStringToBig(amcl.SHA256, test.pub[i])
		}
		for i := range test.priv {
			privBig[i], _ = utils.HashStringToBig(amcl.SHA256, test.priv[i])
		}

		attributes := append(privBig, pubBig...)

		r := Curve.Randomnum(p, rng)
		cm := Curve.G1mul(g1, r)
		for i := range attributes {
			cm.Add(Curve.G1mul(hs[i], attributes[i]))
		}

		b := make([]byte, constants.ECPLen)
		cm.ToBytes(b, true)

		h, _ := utils.HashBytesToG1(amcl.SHA512, b)

		_, gamma := elgamal.Keygen(params.G)

		encs := make([]*elgamal.Encryption, len(test.priv))
		ks := make([]*Curve.BIG, len(test.priv))
		for i := range test.priv {
			c, k := elgamal.Encrypt(params.G, gamma, privBig[i], h)
			encs[i] = c
			ks[i] = k
		}

		signerProof, err := coconut.ConstructSignerProof(params, gamma, encs, cm, ks, r, pubBig, privBig)
		assert.Nil(t, err)

		data, err := signerProof.MarshalBinary()
		assert.Nil(t, err)
		recoveredProof := &coconut.SignerProof{}
		err = recoveredProof.UnmarshalBinary(data)
		assert.Nil(t, err)

		assert.Zero(t, Curve.Comp(signerProof.C(), recoveredProof.C()))
		assert.Zero(t, Curve.Comp(signerProof.Rr(), recoveredProof.Rr()))
		for i := range signerProof.Rk() {
			assert.Zero(t, Curve.Comp(signerProof.Rk()[i], recoveredProof.Rk()[i]))
		}

		for i := range signerProof.Rm() {
			assert.Zero(t, Curve.Comp(signerProof.Rm()[i], recoveredProof.Rm()[i]))
		}

		// sanity check
		assert.True(t, coconut.VerifySignerProof(params, gamma, coconut.NewBlindSignMats(cm, encs, signerProof)))
		assert.True(t, coconut.VerifySignerProof(params, gamma, coconut.NewBlindSignMats(cm, encs, recoveredProof)))

	}
}
