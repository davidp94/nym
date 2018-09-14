package coconut

import (
	"testing"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

func TestSchemeSetup(t *testing.T) {

}

func TestSchemeKeygen(t *testing.T) {

}

func TestSchemeSign(t *testing.T) {
	params := Setup(1)
	G := params.G
	sk, _ := Keygen(params)

	m := "Hello World!"
	var err error
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig, err := Sign(params, sk, []*BLS381.BIG{mBig})
	if err != nil {
		t.Error(err)
	}

	t1 := BLS381.NewBIGcopy(sk.x)
	t1 = t1.Plus(BLS381.Modmul(mBig, sk.y[0], G.Ord))
	sigTest := BLS381.G1mul(sig.sig1, t1)

	if !sigTest.Equals(sig.sig2) {
		t.Error("For single attribute sig2 != (x + m * y) * sig1")
	}

	attr1 := "Attribute 1"
	attr1Big, err := utils.HashStringToBig(amcl.SHA256, attr1)
	if err != nil {
		t.Error(err)
	}
	attr2 := "Attribute 2"

	attr2Big, err := utils.HashStringToBig(amcl.SHA256, attr2)
	if err != nil {
		t.Error(err)
	}

	attr3 := "Attribute 3"
	attr3Big, err := utils.HashStringToBig(amcl.SHA256, attr3)
	if err != nil {
		t.Error(err)
	}

	params2 := Setup(3)
	G2 := params2.G
	skMultiple, _ := Keygen(params2)
	sigMultiple, err := Sign(params2, skMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big})
	if err != nil {
		t.Error(err)
	}

	t2 := BLS381.NewBIGcopy(skMultiple.x)
	t2 = t2.Plus(BLS381.Modmul(attr1Big, skMultiple.y[0], G2.Ord))
	t2 = t2.Plus(BLS381.Modmul(attr2Big, skMultiple.y[1], G2.Ord))
	t2 = t2.Plus(BLS381.Modmul(attr3Big, skMultiple.y[2], G2.Ord))
	sigTest2 := BLS381.G1mul(sigMultiple.sig1, t2)

	if !sigTest2.Equals(sigMultiple.sig2) {
		t.Error("For three attributes sig2 != (x + m1 * y1 + m2 * y2 + m3 * y3) * sig1")
	}

}

func TestSchemeVerify(t *testing.T) {
	params := Setup(1)
	sk, vk := Keygen(params)

	m := "Hello World!"
	var err error
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig, err := Sign(params, sk, []*BLS381.BIG{mBig})
	if err != nil {
		t.Error(err)
	}

	isValid := Verify(params, vk, []*BLS381.BIG{mBig}, sig)
	if !isValid {
		t.Error("Does not correctly verify a valid signature")
	}

	m2 := "Malicious Hello World!"
	mBig2, err := utils.HashStringToBig(amcl.SHA256, m2)
	if err != nil {
		t.Error(err)
	}

	sig2, err := Sign(params, sk, []*BLS381.BIG{mBig2})
	if err != nil {
		t.Error(err)
	}
	isValid2 := Verify(params, vk, []*BLS381.BIG{mBig}, sig2)
	if isValid2 {
		t.Error("Verifies signature of invalid message (Given sig)")
	}

	isValid3 := Verify(params, vk, []*BLS381.BIG{mBig2}, sig)
	if isValid3 {
		t.Error("Verifies invalid signature on different message (Given msg)")
	}

	attr1 := "Attribute 1"
	attr1Big, err := utils.HashStringToBig(amcl.SHA256, attr1)
	if err != nil {
		t.Error(err)
	}
	attr2 := "Attribute 2"

	attr2Big, err := utils.HashStringToBig(amcl.SHA256, attr2)
	if err != nil {
		t.Error(err)
	}

	attr3 := "Attribute 3"
	attr3Big, err := utils.HashStringToBig(amcl.SHA256, attr3)
	if err != nil {
		t.Error(err)
	}

	params2 := Setup(3)
	skMultiple, vkMultiple := Keygen(params2)
	sigMultiple, err := Sign(params2, skMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big})
	if err != nil {
		t.Error(err)
	}

	isValid4 := Verify(params2, vkMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big}, sigMultiple)

	if !isValid4 {
		t.Error("Does not verify signature with multiple public attributes")
	}
}

func TestSchemeRandomize(t *testing.T) {
	params := Setup(1)
	sk, vk := Keygen(params)

	m := "Hello World!"
	var err error
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig, err := Sign(params, sk, []*BLS381.BIG{mBig})
	if err != nil {
		t.Error(err)
	}

	randSig := Randomize(params, sig)

	isValid := Verify(params, vk, []*BLS381.BIG{mBig}, randSig)
	if !isValid {
		t.Error("Does not correctly verify a valid randomized signature")
	}
}

func TestSchemeKeyAggregation(t *testing.T) {
	params := Setup(1)
	sk, vk := Keygen(params)

	m := "Hello World!"
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig, err := Sign(params, sk, []*BLS381.BIG{mBig})
	if err != nil {
		t.Error(err)
	}
	avk := AggregateVerificationKeys(params, []*VerificationKey{vk})

	isValid := Verify(params, avk, []*BLS381.BIG{mBig}, sig)
	if !isValid {
		t.Error("Does not correctly verify an aggregation of a single set of keys")
	}
}

// todo: add more tests for multiple attributes
func TestSchemeAggregateVerification(t *testing.T) {
	params := Setup(1)
	sk, vk := Keygen(params)

	m := "Hello World!"
	var err error
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig, err := Sign(params, sk, []*BLS381.BIG{mBig})
	if err != nil {
		t.Error(err)
	}
	aSig := AggregateSignatures(params, []*Signature{sig})

	isValid := Verify(params, vk, []*BLS381.BIG{mBig}, aSig)
	if !isValid {
		t.Error("Does not correctly verify an aggregation of a single signature")
	}

	signatures := []*Signature{}
	vks := []*VerificationKey{}

	messagesToSign := 3
	for i := 0; i < messagesToSign; i++ {
		sk, vk := Keygen(params)
		vks = append(vks, vk)
		sige, err := Sign(params, sk, []*BLS381.BIG{mBig})
		if err != nil {
			t.Error(err)
		}
		signatures = append(signatures, sige)
	}

	avk := AggregateVerificationKeys(params, vks)
	aSig = AggregateSignatures(params, signatures)

	isValid2 := Verify(params, avk, []*BLS381.BIG{mBig}, aSig)
	if !isValid2 {
		t.Error("Does not correctly verify aggregation of signatures from 3 different entities")
	}

	m2 := "Malicious Hello World!"
	mBig2, err := utils.HashStringToBig(amcl.SHA256, m2)
	if err != nil {
		t.Error(err)
	}

	msk, mvk := Keygen(params)
	vks = append(vks, mvk)
	sige, err := Sign(params, msk, []*BLS381.BIG{mBig2})
	if err != nil {
		t.Error(err)
	}
	signatures = append(signatures, sige)

	avk2 := AggregateVerificationKeys(params, vks)
	aSig2 := AggregateSignatures(params, signatures)

	isValid3 := Verify(params, avk2, []*BLS381.BIG{mBig}, aSig2)
	if isValid3 {
		t.Error("Does not fail if one signature is on different message")
	}
}

func TestSchemeBlindVerifyOnlyPublic(t *testing.T) {
	params := Setup(6)
	_, gamma := elgamal.Keygen(params.G)

	pub := []string{"Foo", "Bar", "Baz"}
	var err error

	pubBig := make([]*BLS381.BIG, len(pub))
	privBig := []*BLS381.BIG{}
	for i := range pub {
		pubBig[i], err = utils.HashStringToBig(amcl.SHA256, pub[i])
		if err != nil {
			t.Error(err)
		}
	}

	_, err = PrepareBlindSign(params, gamma, pubBig, privBig)
	if err == nil {
		t.Error("PrepareBlindSign did not throw an error when there were no private attributes to sign")
	}

}

func TestSchemeBlindVerifyOnlyPrivate(t *testing.T) {
	params := Setup(3)
	sk, vk := Keygen(params)
	d, gamma := elgamal.Keygen(params.G)

	priv := []string{"Foo2", "Bar2", "Baz2"}
	var err error

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

	if !BlindVerify(params, vk, sig, blindShowMats, pubBig) {
		t.Error("Failed to verify blind signature on multiple private and no public attributes")
	}
	if !Verify(params, vk, append(privBig, pubBig...), sig) {
		t.Error("Failed to verify blind signature on multiple private and no public attributes after revealing all private attributes")
	}
}

func TestSchemeBlindVerifyMixedAttributes(t *testing.T) {
	params := Setup(6)
	sk, vk := Keygen(params)
	d, gamma := elgamal.Keygen(params.G)

	pub := []string{"Foo", "Bar", "Baz"}
	priv := []string{"Foo2", "Bar2", "Baz2"}
	var err error

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

	if !BlindVerify(params, vk, sig, blindShowMats, pubBig) {
		t.Error("Failed to verify blind signature on multiple private and public attributes")
	}
	if !Verify(params, vk, append(privBig, pubBig...), sig) {
		t.Error("Failed to verify blind signature on multiple private and public attributes after revealing all private attributes")
	}
}
