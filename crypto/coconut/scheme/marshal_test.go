package coconut_test

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
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

		_, egPub := elgamal.Keygen(params.G)

		encs := make([]*elgamal.Encryption, len(test.priv))
		ks := make([]*Curve.BIG, len(test.priv))
		for i := range test.priv {
			c, k := elgamal.Encrypt(params.G, egPub, privBig[i], h)
			encs[i] = c
			ks[i] = k
		}

		signerProof, err := coconut.ConstructSignerProof(params, egPub.Gamma(), encs, cm, ks, r, pubBig, privBig)
		if len(test.priv) == 0 {
			assert.Nil(t, signerProof)
			assert.Error(t, err)
			continue // everything beyond is undefined behaviour
		} else {
			assert.Nil(t, err)
		}

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
		assert.True(t, coconut.VerifySignerProof(params, egPub.Gamma(), coconut.NewLambda(cm, encs, signerProof)))
		assert.True(t, coconut.VerifySignerProof(params, egPub.Gamma(), coconut.NewLambda(cm, encs, recoveredProof)))

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

		_, egPub := elgamal.Keygen(params.G)
		blindSignMats, _ := coconut.PrepareBlindSign(params, egPub, pubBig, privBig)

		data, err := blindSignMats.MarshalBinary()

		assert.Nil(t, err)
		recoveredBlindSignMats := &coconut.Lambda{}
		assert.Nil(t, recoveredBlindSignMats.UnmarshalBinary(data))

		assert.True(t, blindSignMats.Cm().Equals(recoveredBlindSignMats.Cm()))
		for i := range blindSignMats.Enc() {
			assert.True(t, blindSignMats.Enc()[i].C1().Equals(recoveredBlindSignMats.Enc()[i].C1()))
			assert.True(t, blindSignMats.Enc()[i].C2().Equals(recoveredBlindSignMats.Enc()[i].C2()))
		}

		assert.Zero(t, Curve.Comp(blindSignMats.Proof().C(), recoveredBlindSignMats.Proof().C()))
		assert.Zero(t, Curve.Comp(blindSignMats.Proof().Rr(), recoveredBlindSignMats.Proof().Rr()))
		for i := range blindSignMats.Proof().Rk() {
			assert.Zero(t, Curve.Comp(blindSignMats.Proof().Rk()[i], recoveredBlindSignMats.Proof().Rk()[i]))
		}

		for i := range blindSignMats.Proof().Rm() {
			assert.Zero(t, Curve.Comp(blindSignMats.Proof().Rm()[i], recoveredBlindSignMats.Proof().Rm()[i]))
		}

		// sanity check
		assert.True(t, coconut.VerifySignerProof(params, egPub.Gamma(), blindSignMats))
		assert.True(t, coconut.VerifySignerProof(params, egPub.Gamma(), recoveredBlindSignMats))
	}
}

// nolint: lll
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
		theta, _ := coconut.ShowBlindSignature(params, vk, sig, privBig)

		verifierProof := theta.Proof()
		data, err := verifierProof.MarshalBinary()
		assert.Nil(t, err)
		recoveredProof := &coconut.VerifierProof{}
		assert.Nil(t, recoveredProof.UnmarshalBinary(data))

		assert.Zero(t, Curve.Comp(verifierProof.C(), recoveredProof.C()))
		assert.Zero(t, Curve.Comp(verifierProof.Rt(), recoveredProof.Rt()))
		for i := range verifierProof.Rm() {
			assert.Zero(t, Curve.Comp(verifierProof.Rm()[i], recoveredProof.Rm()[i]))
		}

		assert.True(t, coconut.VerifyVerifierProof(params, vk, sig, theta))
		assert.True(t, coconut.VerifyVerifierProof(params, vk, sig, coconut.NewTheta(theta.Kappa(), theta.Nu(), recoveredProof)))

	}
}

func TestThetaMarshal(t *testing.T) {
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
		theta, _ := coconut.ShowBlindSignature(params, vk, sig, privBig)

		data, err := theta.MarshalBinary()
		assert.Nil(t, err)
		recoveredtheta := &coconut.Theta{}
		assert.Nil(t, recoveredtheta.UnmarshalBinary(data))

		assert.True(t, theta.Kappa().Equals(recoveredtheta.Kappa()))
		assert.True(t, theta.Nu().Equals(recoveredtheta.Nu()))

		assert.Zero(t, Curve.Comp(theta.Proof().C(), recoveredtheta.Proof().C()))
		assert.Zero(t, Curve.Comp(theta.Proof().Rt(), recoveredtheta.Proof().Rt()))
		for i := range theta.Proof().Rm() {
			assert.Zero(t, Curve.Comp(theta.Proof().Rm()[i], recoveredtheta.Proof().Rm()[i]))
		}

		// sanity checks
		assert.True(t, bool(coconut.BlindVerify(params, vk, sig, theta, pubBig)))
		assert.True(t, bool(coconut.BlindVerify(params, vk, sig, recoveredtheta, pubBig)))
	}
}
