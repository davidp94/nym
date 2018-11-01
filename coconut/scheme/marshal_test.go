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
		{pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"}},
		{pub: []string{"Foo"}, priv: []string{}},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{}},
		{pub: []string{"Foo"}, priv: []string{"Foo2"}},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}},
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
		assert.Nil(t, recoveredProof.UnmarshalBinary(data))

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

func TestBlindSignMatsMarshal(t *testing.T) {
	tests := []struct {
		pub  []string
		priv []string
	}{
		{pub: []string{}, priv: []string{"Foo2"}},
		{pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"}},
		{pub: []string{"Foo"}, priv: []string{"Foo2"}},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}},
		{pub: []string{}, priv: []string{
			"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8",
			"B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8",
			"C1", "C2", "C3", "C4", "C5", "C6", "C7",
		}},
		{pub: []string{}, priv: []string{
			"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8",
			"B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8",
			"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8",
		}},
	}

	for _, test := range tests {
		params, _ := coconut.Setup(len(test.pub) + len(test.priv))

		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))

		for i := range test.pub {
			pubBig[i], _ = utils.HashStringToBig(amcl.SHA256, test.pub[i])
		}
		for i := range test.priv {
			privBig[i], _ = utils.HashStringToBig(amcl.SHA256, test.priv[i])
		}

		_, gamma := elgamal.Keygen(params.G)
		blindSignMats, _ := coconut.PrepareBlindSign(params, gamma, pubBig, privBig)

		data, err := blindSignMats.MarshalBinary()
		if !constants.MarshalEmbedHelperData && len(test.priv) > constants.MB/2-1 {
			assert.NotNil(t, err)
			continue
		}

		assert.Nil(t, err)
		recoveredBlindSignMats := &coconut.BlindSignMats{}
		assert.Nil(t, recoveredBlindSignMats.UnmarshalBinary(data))

		assert.True(t, blindSignMats.Cm().Equals(recoveredBlindSignMats.Cm()))
		for i := range blindSignMats.Enc() {
			assert.True(t, blindSignMats.Enc()[i].C1().Equals(recoveredBlindSignMats.Enc()[i].C1()))
			assert.True(t, blindSignMats.Enc()[i].C2().Equals(recoveredBlindSignMats.Enc()[i].C2()))
		}

		assert.Zero(t, Curve.Comp(blindSignMats.Proof().C(), blindSignMats.Proof().C()))
		assert.Zero(t, Curve.Comp(blindSignMats.Proof().Rr(), blindSignMats.Proof().Rr()))
		for i := range blindSignMats.Proof().Rk() {
			assert.Zero(t, Curve.Comp(blindSignMats.Proof().Rk()[i], blindSignMats.Proof().Rk()[i]))
		}

		for i := range blindSignMats.Proof().Rm() {
			assert.Zero(t, Curve.Comp(blindSignMats.Proof().Rm()[i], blindSignMats.Proof().Rm()[i]))
		}

		// sanity check
		assert.True(t, coconut.VerifySignerProof(params, gamma, blindSignMats))
		assert.True(t, coconut.VerifySignerProof(params, gamma, recoveredBlindSignMats))
	}
}

func TestVerifierProofMarshal(t *testing.T) {
	tests := []struct {
		pub  []string
		priv []string
	}{
		{pub: []string{}, priv: []string{"Foo2"}},
		{pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"}},
		{pub: []string{"Foo"}, priv: []string{"Foo2"}},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}},
	}

	for _, test := range tests {
		params, _ := coconut.Setup(len(test.pub) + len(test.priv))
		sk, vk, _ := coconut.Keygen(params)
		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))
		for i := range test.pub {
			pubBig[i], _ = utils.HashStringToBig(amcl.SHA256, test.pub[i])
		}
		for i := range test.priv {
			privBig[i], _ = utils.HashStringToBig(amcl.SHA256, test.priv[i])
		}

		d, gamma := elgamal.Keygen(params.G)
		blindSignMats, _ := coconut.PrepareBlindSign(params, gamma, pubBig, privBig)
		blindedSignature, _ := coconut.BlindSign(params, sk, blindSignMats, gamma, pubBig)
		sig := coconut.Unblind(params, blindedSignature, d)
		blindShowMats, _ := coconut.ShowBlindSignature(params, vk, sig, privBig)

		verifierProof := blindShowMats.Proof()
		data, err := verifierProof.MarshalBinary()
		assert.Nil(t, err)
		recoveredProof := &coconut.VerifierProof{}
		assert.Nil(t, recoveredProof.UnmarshalBinary(data))

		assert.Zero(t, Curve.Comp(verifierProof.C(), recoveredProof.C()))
		assert.Zero(t, Curve.Comp(verifierProof.Rt(), recoveredProof.Rt()))
		for i := range verifierProof.Rm() {
			assert.Zero(t, Curve.Comp(verifierProof.Rm()[i], recoveredProof.Rm()[i]))
		}

		assert.True(t, coconut.VerifyVerifierProof(params, vk, sig, blindShowMats))
		assert.True(t, coconut.VerifyVerifierProof(params, vk, sig, coconut.NewBlindShowMats(blindShowMats.Kappa(), blindShowMats.Nu(), recoveredProof)))

	}
}

func TestBlindShowMatsMarshal(t *testing.T) {
	tests := []struct {
		pub  []string
		priv []string
	}{
		{pub: []string{}, priv: []string{"Foo2"}},
		{pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"}},
		{pub: []string{"Foo"}, priv: []string{"Foo2"}},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}},
	}

	for _, test := range tests {
		params, _ := coconut.Setup(len(test.pub) + len(test.priv))
		sk, vk, _ := coconut.Keygen(params)
		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))
		for i := range test.pub {
			pubBig[i], _ = utils.HashStringToBig(amcl.SHA256, test.pub[i])
		}
		for i := range test.priv {
			privBig[i], _ = utils.HashStringToBig(amcl.SHA256, test.priv[i])
		}

		d, gamma := elgamal.Keygen(params.G)
		blindSignMats, _ := coconut.PrepareBlindSign(params, gamma, pubBig, privBig)
		blindedSignature, _ := coconut.BlindSign(params, sk, blindSignMats, gamma, pubBig)
		sig := coconut.Unblind(params, blindedSignature, d)
		blindShowMats, _ := coconut.ShowBlindSignature(params, vk, sig, privBig)

		data, err := blindShowMats.MarshalBinary()
		assert.Nil(t, err)
		recoveredBlindShowMats := &coconut.BlindShowMats{}
		assert.Nil(t, recoveredBlindShowMats.UnmarshalBinary(data))

		assert.True(t, blindShowMats.Kappa().Equals(recoveredBlindShowMats.Kappa()))
		assert.True(t, blindShowMats.Nu().Equals(recoveredBlindShowMats.Nu()))

		assert.Zero(t, Curve.Comp(blindShowMats.Proof().C(), recoveredBlindShowMats.Proof().C()))
		assert.Zero(t, Curve.Comp(blindShowMats.Proof().Rt(), recoveredBlindShowMats.Proof().Rt()))
		for i := range blindShowMats.Proof().Rm() {
			assert.Zero(t, Curve.Comp(blindShowMats.Proof().Rm()[i], recoveredBlindShowMats.Proof().Rm()[i]))
		}

		// sanity checks
		assert.True(t, coconut.BlindVerify(params, vk, sig, blindShowMats, pubBig))
		assert.True(t, coconut.BlindVerify(params, vk, sig, recoveredBlindShowMats, pubBig))
	}
}
