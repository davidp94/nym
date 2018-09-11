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
		t.Error("Does not correctly verify valid signature")
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

}

func TestSchemeKeyAggregation(t *testing.T) {

}

func TestSchemeAggregateVerification(t *testing.T) {

}
