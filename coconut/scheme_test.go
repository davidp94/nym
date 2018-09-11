package coconut_test

import (
	"testing"

	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"

	"github.com/jstuczyn/CoconutGo/coconut"
)

func TestSchemeSetup(t *testing.T) {

}

func TestSchemeKeygen(t *testing.T) {

}

func TestSchemeSign(t *testing.T) {

}

// todo: add tests for multiple attributes
func TestSchemeVerify(t *testing.T) {
	G, hs := coconut.Setup(1)
	sk, vk := coconut.Keygen(G, hs)

	m := "Hello World!"
	mBig, err := coconut.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := coconut.Sign(G, sk, []*BLS381.BIG{mBig})

	isValid := coconut.Verify(G, vk, []*BLS381.BIG{mBig}, sig)
	if !isValid {
		t.Error("Does not correctly verify a valid signature")
	}

	m2 := "Malicious Hello World!"
	mBig2, err2 := coconut.HashStringToBig(amcl.SHA256, m2)
	if err2 != nil {
		t.Error(err)
	}

	sig2 := coconut.Sign(G, sk, []*BLS381.BIG{mBig2})
	isValid2 := coconut.Verify(G, vk, []*BLS381.BIG{mBig}, sig2)
	if isValid2 {
		t.Error("Verifies signature of invalid message (Given sig)")
	}

	isValid3 := coconut.Verify(G, vk, []*BLS381.BIG{mBig2}, sig)
	if isValid3 {
		t.Error("Verifies invalid signature on different message (Given msg)")
	}
}

func TestSchemeRandomize(t *testing.T) {
	G, hs := coconut.Setup(1)
	sk, vk := coconut.Keygen(G, hs)

	m := "Hello World!"
	mBig, err := coconut.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := coconut.Sign(G, sk, []*BLS381.BIG{mBig})
	randSig := coconut.Randomize(G, sig)

	isValid := coconut.Verify(G, vk, []*BLS381.BIG{mBig}, randSig)
	if !isValid {
		t.Error("Does not correctly verify a valid randomized signature")
	}
}

func TestSchemeKeyAggregation(t *testing.T) {
	G, hs := coconut.Setup(1)
	sk, vk := coconut.Keygen(G, hs)

	m := "Hello World!"
	mBig, err := coconut.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := coconut.Sign(G, sk, []*BLS381.BIG{mBig})
	avk := coconut.AggregateVerificationKeys(G, [][]*BLS381.ECP2{vk})

	isValid := coconut.Verify(G, avk, []*BLS381.BIG{mBig}, sig)
	if !isValid {
		t.Error("Does not correctly verify an aggregation of a single set of keys")
	}
}

// todo: add more tests for multiple attributes
func TestSchemeAggregateVerification(t *testing.T) {
	G, hs := coconut.Setup(1)
	sk, vk := coconut.Keygen(G, hs)

	m := "Hello World!"
	mBig, err := coconut.HashStringToBig(amcl.SHA256, m)
	if err != nil {
		t.Error(err)
	}
	sig := coconut.Sign(G, sk, []*BLS381.BIG{mBig})
	aSig := coconut.AggregateSignatures(G, []coconut.Signature{sig})

	isValid := coconut.Verify(G, vk, []*BLS381.BIG{mBig}, aSig)
	if !isValid {
		t.Error("Does not correctly verify an aggregation of a single signature")
	}

	signatures := []coconut.Signature{}
	vks := [][]*BLS381.ECP2{}

	messagesToSign := 3
	for i := 0; i < messagesToSign; i++ {
		sk, vk := coconut.Keygen(G, hs)
		vks = append(vks, vk)
		signatures = append(signatures, coconut.Sign(G, sk, []*BLS381.BIG{mBig}))
	}

	avk := coconut.AggregateVerificationKeys(G, vks)
	aSig = coconut.AggregateSignatures(G, signatures)

	isValid2 := coconut.Verify(G, avk, []*BLS381.BIG{mBig}, aSig)
	if !isValid2 {
		t.Error("Does not correctly verify aggregation of signatures from 3 different entities")
	}

	m2 := "Malicious Hello World!"
	mBig2, err2 := coconut.HashStringToBig(amcl.SHA256, m2)
	if err2 != nil {
		t.Error(err)
	}

	msk, mvk := coconut.Keygen(G, hs)
	vks = append(vks, mvk)
	signatures = append(signatures, coconut.Sign(G, msk, []*BLS381.BIG{mBig2}))

	avk2 := coconut.AggregateVerificationKeys(G, vks)
	aSig2 := coconut.AggregateSignatures(G, signatures)

	isValid3 := coconut.Verify(G, avk2, []*BLS381.BIG{mBig}, aSig2)
	if isValid3 {
		t.Error("Does not fail if one signature is on different message")
	}
}
