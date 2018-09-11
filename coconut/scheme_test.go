package coconut

import (
	"testing"

	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

func TestSchemeSetup(t *testing.T) {

}

func TestSchemeKeygen(t *testing.T) {

}

func TestSchemeSign(t *testing.T) {
	G, hs := Setup(1)
	sk, _ := Keygen(G, hs)

	m := "Hello World!"
	mBig, err := HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(G, sk, []*BLS381.BIG{mBig})

	t1 := BLS381.NewBIGcopy(sk[0])
	t1 = t1.Plus(BLS381.Modmul(mBig, sk[1], G.Ord))
	sigTest := BLS381.G1mul(sig.sig1, t1)

	if !sigTest.Equals(sig.sig2) {
		t.Error("For single attribute sig2 != (x + m * y) * sig1")
	}

	attr1 := "Attribute 1"
	attr1Big, err1 := HashStringToBig(amcl.SHA256, attr1)
	if err1 != nil {
		t.Error(err)
	}
	attr2 := "Attribute 2"

	attr2Big, err2 := HashStringToBig(amcl.SHA256, attr2)
	if err2 != nil {
		t.Error(err)
	}

	attr3 := "Attribute 3"
	attr3Big, err3 := HashStringToBig(amcl.SHA256, attr3)
	if err3 != nil {
		t.Error(err)
	}

	G2, hs2 := Setup(3)
	skMultiple, _ := Keygen(G2, hs2)
	sigMultiple := Sign(G2, skMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big})

	t2 := BLS381.NewBIGcopy(skMultiple[0])
	t2 = t2.Plus(BLS381.Modmul(attr1Big, skMultiple[1], G.Ord))
	t2 = t2.Plus(BLS381.Modmul(attr2Big, skMultiple[2], G.Ord))
	t2 = t2.Plus(BLS381.Modmul(attr3Big, skMultiple[3], G.Ord))
	sigTest2 := BLS381.G1mul(sigMultiple.sig1, t2)

	if !sigTest2.Equals(sigMultiple.sig2) {
		t.Error("For three attributes sig2 != (x + m1 * y1 + m2 * y2 + m3 * y3) * sig1")
	}

}

func TestSchemeVerify(t *testing.T) {
	G, hs := Setup(1)
	sk, vk := Keygen(G, hs)

	m := "Hello World!"
	mBig, err := HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(G, sk, []*BLS381.BIG{mBig})

	isValid := Verify(G, vk, []*BLS381.BIG{mBig}, sig)
	if !isValid {
		t.Error("Does not correctly verify a valid signature")
	}

	m2 := "Malicious Hello World!"
	mBig2, err2 := HashStringToBig(amcl.SHA256, m2)
	if err2 != nil {
		t.Error(err)
	}

	sig2 := Sign(G, sk, []*BLS381.BIG{mBig2})
	isValid2 := Verify(G, vk, []*BLS381.BIG{mBig}, sig2)
	if isValid2 {
		t.Error("Verifies signature of invalid message (Given sig)")
	}

	isValid3 := Verify(G, vk, []*BLS381.BIG{mBig2}, sig)
	if isValid3 {
		t.Error("Verifies invalid signature on different message (Given msg)")
	}

	attr1 := "Attribute 1"
	attr1Big, err1 := HashStringToBig(amcl.SHA256, attr1)
	if err1 != nil {
		t.Error(err)
	}
	attr2 := "Attribute 2"

	attr2Big, err2 := HashStringToBig(amcl.SHA256, attr2)
	if err2 != nil {
		t.Error(err)
	}

	attr3 := "Attribute 3"
	attr3Big, err3 := HashStringToBig(amcl.SHA256, attr3)
	if err3 != nil {
		t.Error(err)
	}

	G2, hs2 := Setup(3)
	skMultiple, vkMultiple := Keygen(G2, hs2)
	sigMultiple := Sign(G2, skMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big})

	isValid4 := Verify(G2, vkMultiple, []*BLS381.BIG{attr1Big, attr2Big, attr3Big}, sigMultiple)

	if !isValid4 {
		t.Error("Does not verify signature with multiple public attributes")
	}
}

func TestSchemeRandomize(t *testing.T) {
	G, hs := Setup(1)
	sk, vk := Keygen(G, hs)

	m := "Hello World!"
	mBig, err := HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(G, sk, []*BLS381.BIG{mBig})
	randSig := Randomize(G, sig)

	isValid := Verify(G, vk, []*BLS381.BIG{mBig}, randSig)
	if !isValid {
		t.Error("Does not correctly verify a valid randomized signature")
	}
}

func TestSchemeKeyAggregation(t *testing.T) {
	G, hs := Setup(1)
	sk, vk := Keygen(G, hs)

	m := "Hello World!"
	mBig, err := HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(G, sk, []*BLS381.BIG{mBig})
	avk := AggregateVerificationKeys(G, [][]*BLS381.ECP2{vk})

	isValid := Verify(G, avk, []*BLS381.BIG{mBig}, sig)
	if !isValid {
		t.Error("Does not correctly verify an aggregation of a single set of keys")
	}
}

// todo: add more tests for multiple attributes
func TestSchemeAggregateVerification(t *testing.T) {
	G, hs := Setup(1)
	sk, vk := Keygen(G, hs)

	m := "Hello World!"
	mBig, err := HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := Sign(G, sk, []*BLS381.BIG{mBig})
	aSig := AggregateSignatures(G, []Signature{sig})

	isValid := Verify(G, vk, []*BLS381.BIG{mBig}, aSig)
	if !isValid {
		t.Error("Does not correctly verify an aggregation of a single signature")
	}

	signatures := []Signature{}
	vks := [][]*BLS381.ECP2{}

	messagesToSign := 3
	for i := 0; i < messagesToSign; i++ {
		sk, vk := Keygen(G, hs)
		vks = append(vks, vk)
		signatures = append(signatures, Sign(G, sk, []*BLS381.BIG{mBig}))
	}

	avk := AggregateVerificationKeys(G, vks)
	aSig = AggregateSignatures(G, signatures)

	isValid2 := Verify(G, avk, []*BLS381.BIG{mBig}, aSig)
	if !isValid2 {
		t.Error("Does not correctly verify aggregation of signatures from 3 different entities")
	}

	m2 := "Malicious Hello World!"
	mBig2, err2 := HashStringToBig(amcl.SHA256, m2)
	if err2 != nil {
		t.Error(err)
	}

	msk, mvk := Keygen(G, hs)
	vks = append(vks, mvk)
	signatures = append(signatures, Sign(G, msk, []*BLS381.BIG{mBig2}))

	avk2 := AggregateVerificationKeys(G, vks)
	aSig2 := AggregateSignatures(G, signatures)

	isValid3 := Verify(G, avk2, []*BLS381.BIG{mBig}, aSig2)
	if isValid3 {
		t.Error("Does not fail if one signature is on different message")
	}
}
