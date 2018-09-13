package coconut

import (
	"testing"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
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
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(params, sk, []*BLS381.BIG{mBig})

	t1 := BLS381.NewBIGcopy(sk[0])
	t1 = t1.Plus(BLS381.Modmul(mBig, sk[1], G.Ord))
	sigTest := BLS381.G1mul(sig.sig1, t1)

	if !sigTest.Equals(sig.sig2) {
		t.Error("For single attribute sig2 != (x + m * y) * sig1")
	}

	attr1 := "Attribute 1"
	attr1Big, err1 := utils.HashStringToBig(amcl.SHA256, attr1)
	if err1 != nil {
		t.Error(err)
	}
	attr2 := "Attribute 2"

	attr2Big, err2 := utils.HashStringToBig(amcl.SHA256, attr2)
	if err2 != nil {
		t.Error(err)
	}

	attr3 := "Attribute 3"
	attr3Big, err3 := utils.HashStringToBig(amcl.SHA256, attr3)
	if err3 != nil {
		t.Error(err)
	}

	params2 := Setup(3)
	G2 := params2.G
	skMultiple, _ := Keygen(params2)
	sigMultiple := Sign(params2, skMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big})

	t2 := BLS381.NewBIGcopy(skMultiple[0])
	t2 = t2.Plus(BLS381.Modmul(attr1Big, skMultiple[1], G2.Ord))
	t2 = t2.Plus(BLS381.Modmul(attr2Big, skMultiple[2], G2.Ord))
	t2 = t2.Plus(BLS381.Modmul(attr3Big, skMultiple[3], G2.Ord))
	sigTest2 := BLS381.G1mul(sigMultiple.sig1, t2)

	if !sigTest2.Equals(sigMultiple.sig2) {
		t.Error("For three attributes sig2 != (x + m1 * y1 + m2 * y2 + m3 * y3) * sig1")
	}

}

func TestSchemeVerify(t *testing.T) {
	params := Setup(1)
	sk, vk := Keygen(params)

	m := "Hello World!"
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(params, sk, []*BLS381.BIG{mBig})

	isValid := Verify(params, vk, []*BLS381.BIG{mBig}, sig)
	if !isValid {
		t.Error("Does not correctly verify a valid signature")
	}

	m2 := "Malicious Hello World!"
	mBig2, err2 := utils.HashStringToBig(amcl.SHA256, m2)
	if err2 != nil {
		t.Error(err)
	}

	sig2 := Sign(params, sk, []*BLS381.BIG{mBig2})
	isValid2 := Verify(params, vk, []*BLS381.BIG{mBig}, sig2)
	if isValid2 {
		t.Error("Verifies signature of invalid message (Given sig)")
	}

	isValid3 := Verify(params, vk, []*BLS381.BIG{mBig2}, sig)
	if isValid3 {
		t.Error("Verifies invalid signature on different message (Given msg)")
	}

	attr1 := "Attribute 1"
	attr1Big, err1 := utils.HashStringToBig(amcl.SHA256, attr1)
	if err1 != nil {
		t.Error(err)
	}
	attr2 := "Attribute 2"

	attr2Big, err2 := utils.HashStringToBig(amcl.SHA256, attr2)
	if err2 != nil {
		t.Error(err)
	}

	attr3 := "Attribute 3"
	attr3Big, err3 := utils.HashStringToBig(amcl.SHA256, attr3)
	if err3 != nil {
		t.Error(err)
	}

	params2 := Setup(3)
	skMultiple, vkMultiple := Keygen(params2)
	sigMultiple := Sign(params2, skMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big})

	isValid4 := Verify(params2, vkMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big}, sigMultiple)

	if !isValid4 {
		t.Error("Does not verify signature with multiple public attributes")
	}
}

func TestSchemeRandomize(t *testing.T) {
	params := Setup(1)
	sk, vk := Keygen(params)

	m := "Hello World!"
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(params, sk, []*BLS381.BIG{mBig})
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
	sig := Sign(params, sk, []*BLS381.BIG{mBig})
	avk := AggregateVerificationKeys(params, [][]*BLS381.ECP2{vk})

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
	mBig, err := utils.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(params, sk, []*BLS381.BIG{mBig})
	aSig := AggregateSignatures(params, []*Signature{sig})

	isValid := Verify(params, vk, []*BLS381.BIG{mBig}, aSig)
	if !isValid {
		t.Error("Does not correctly verify an aggregation of a single signature")
	}

	signatures := []*Signature{}
	vks := [][]*BLS381.ECP2{}

	messagesToSign := 3
	for i := 0; i < messagesToSign; i++ {
		sk, vk := Keygen(params)
		vks = append(vks, vk)
		signatures = append(signatures, Sign(params, sk, []*BLS381.BIG{mBig}))
	}

	avk := AggregateVerificationKeys(params, vks)
	aSig = AggregateSignatures(params, signatures)

	isValid2 := Verify(params, avk, []*BLS381.BIG{mBig}, aSig)
	if !isValid2 {
		t.Error("Does not correctly verify aggregation of signatures from 3 different entities")
	}

	m2 := "Malicious Hello World!"
	mBig2, err2 := utils.HashStringToBig(amcl.SHA256, m2)
	if err2 != nil {
		t.Error(err)
	}

	msk, mvk := Keygen(params)
	vks = append(vks, mvk)
	signatures = append(signatures, Sign(params, msk, []*BLS381.BIG{mBig2}))

	avk2 := AggregateVerificationKeys(params, vks)
	aSig2 := AggregateSignatures(params, signatures)

	isValid3 := Verify(params, avk2, []*BLS381.BIG{mBig}, aSig2)
	if isValid3 {
		t.Error("Does not fail if one signature is on different message")
	}
}
