package coconut

import (
	"testing"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

func TestVerifySignerProofSinglePrivate(t *testing.T) {
	params := Setup(1)
	priv := []string{"Bar"}

	privBig := make([]*BLS381.BIG, len(priv))
	for i := range priv {
		privBig[i], _ = utils.HashStringToBig(amcl.SHA256, priv[i])
	}

	r := BLS381.Randomnum(params.G.Ord, params.G.Rng)
	cm := BLS381.G1mul(params.G.Gen1, r)
	for i := range privBig {
		cm.Add(BLS381.G1mul(params.Hs[i], privBig[i]))
	}
	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
	if err != nil {
		t.Error(err)
	}

	_, gamma := elgamal.Keygen(params.G)
	encs := make([]*elgamal.ElGamalEncryption, len(priv))
	ks := make([]*BLS381.BIG, len(priv))
	for i := range priv {
		c, k := elgamal.Encrypt(params.G, gamma, privBig[i], h)
		encs[i] = c
		ks[i] = k
	}

	signerProof, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, []*BLS381.BIG{}, privBig)
	if err != nil {
		t.Error(nil)
	}

	isProofValid := VerifySignerProof(params, gamma, encs, cm, signerProof)
	if !isProofValid {
		t.Error("The signer proof is invalid for single private attribute (no public)")
	}

}

func TestVerifySignerProofMultiplePrivate(t *testing.T) {
	params := Setup(3)
	priv := []string{"Foo", "Bar", "Baz"}

	privBig := make([]*BLS381.BIG, len(priv))
	for i := range priv {
		privBig[i], _ = utils.HashStringToBig(amcl.SHA256, priv[i])
	}

	r := BLS381.Randomnum(params.G.Ord, params.G.Rng)
	cm := BLS381.G1mul(params.G.Gen1, r)
	for i := range privBig {
		cm.Add(BLS381.G1mul(params.Hs[i], privBig[i]))
	}
	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
	if err != nil {
		t.Error(err)
	}

	_, gamma := elgamal.Keygen(params.G)
	encs := make([]*elgamal.ElGamalEncryption, len(priv))
	ks := make([]*BLS381.BIG, len(priv))
	for i := range priv {
		c, k := elgamal.Encrypt(params.G, gamma, privBig[i], h)
		encs[i] = c
		ks[i] = k
	}

	signerProof, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, []*BLS381.BIG{}, privBig)
	if err != nil {
		t.Error(nil)
	}

	isProofValid := VerifySignerProof(params, gamma, encs, cm, signerProof)
	if !isProofValid {
		t.Error("The signer proof is invalid for three private attribute (no public)")
	}
}

func TestVerifySignerProofSinglePublic(t *testing.T) {
	params := Setup(1)
	pub := []string{"Foo"}

	pubBig := make([]*BLS381.BIG, len(pub))
	for i := range pub {
		pubBig[i], _ = utils.HashStringToBig(amcl.SHA256, pub[i])
	}

	r := BLS381.Randomnum(params.G.Ord, params.G.Rng)
	cm := BLS381.G1mul(params.G.Gen1, r)
	for i := range pub {
		cm.Add(BLS381.G1mul(params.Hs[i], pubBig[i]))
	}

	signerProof, err := ConstructSignerProof(params, nil, []*elgamal.ElGamalEncryption{}, cm, []*BLS381.BIG{}, r, pubBig, []*BLS381.BIG{})
	if err != nil {
		t.Error(nil)
	}

	isProofValid := VerifySignerProof(params, nil, []*elgamal.ElGamalEncryption{}, cm, signerProof)
	if !isProofValid {
		t.Error("The signer proof is invalid for single public attribute (no private)")
	}
}

func TestVerifySignerProofMultiplePublic(t *testing.T) {
	params := Setup(3)
	pub := []string{"Foo", "Bar", "Baz"}

	pubBig := make([]*BLS381.BIG, len(pub))
	for i := range pub {
		pubBig[i], _ = utils.HashStringToBig(amcl.SHA256, pub[i])
	}

	r := BLS381.Randomnum(params.G.Ord, params.G.Rng)
	cm := BLS381.G1mul(params.G.Gen1, r)
	for i := range pub {
		cm.Add(BLS381.G1mul(params.Hs[i], pubBig[i]))
	}

	signerProof, err := ConstructSignerProof(params, nil, []*elgamal.ElGamalEncryption{}, cm, []*BLS381.BIG{}, r, pubBig, []*BLS381.BIG{})
	if err != nil {
		t.Error(nil)
	}

	isProofValid := VerifySignerProof(params, nil, []*elgamal.ElGamalEncryption{}, cm, signerProof)
	if !isProofValid {
		t.Error("The signer proof is invalid for three public attribute (no private)")
	}
}

func TestVerifySignerProofSingleMixed(t *testing.T) {
	params := Setup(2)
	pub := []string{"Foo"}
	priv := []string{"Bar"}

	pubBig := make([]*BLS381.BIG, len(pub))
	privBig := make([]*BLS381.BIG, len(priv))
	for i := range pub {
		pubBig[i], _ = utils.HashStringToBig(amcl.SHA256, pub[i])
	}
	for i := range priv {
		privBig[i], _ = utils.HashStringToBig(amcl.SHA256, priv[i])
	}
	attributes := append(privBig, pubBig...)

	r := BLS381.Randomnum(params.G.Ord, params.G.Rng)
	cm := BLS381.G1mul(params.G.Gen1, r)
	for i := range attributes {
		cm.Add(BLS381.G1mul(params.Hs[i], attributes[i]))
	}
	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
	if err != nil {
		t.Error(err)
	}

	_, gamma := elgamal.Keygen(params.G)
	encs := make([]*elgamal.ElGamalEncryption, len(priv))
	ks := make([]*BLS381.BIG, len(priv))
	for i := range priv {
		c, k := elgamal.Encrypt(params.G, gamma, privBig[i], h)
		encs[i] = c
		ks[i] = k
	}

	signerProof, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, pubBig, privBig)
	if err != nil {
		t.Error(nil)
	}

	isProofValid := VerifySignerProof(params, gamma, encs, cm, signerProof)
	if !isProofValid {
		t.Error("The signer proof is invalid for single public and single private attribute")
	}
}

func TestVerifySignerProofMultipleMixed(t *testing.T) {
	params := Setup(6)
	pub := []string{"Foo", "Bar", "Baz"}
	priv := []string{"Foo2", "Bar2", "Baz2"}

	pubBig := make([]*BLS381.BIG, len(pub))
	privBig := make([]*BLS381.BIG, len(priv))
	for i := range pub {
		pubBig[i], _ = utils.HashStringToBig(amcl.SHA256, pub[i])
	}
	for i := range priv {
		privBig[i], _ = utils.HashStringToBig(amcl.SHA256, priv[i])
	}
	attributes := append(privBig, pubBig...)

	r := BLS381.Randomnum(params.G.Ord, params.G.Rng)
	cm := BLS381.G1mul(params.G.Gen1, r)
	for i := range attributes {
		cm.Add(BLS381.G1mul(params.Hs[i], attributes[i]))
	}
	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
	if err != nil {
		t.Error(err)
	}

	_, gamma := elgamal.Keygen(params.G)
	encs := make([]*elgamal.ElGamalEncryption, len(priv))
	ks := make([]*BLS381.BIG, len(priv))
	for i := range priv {
		c, k := elgamal.Encrypt(params.G, gamma, privBig[i], h)
		encs[i] = c
		ks[i] = k
	}

	signerProof, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, pubBig, privBig)
	if err != nil {
		t.Error(nil)
	}

	isProofValid := VerifySignerProof(params, gamma, encs, cm, signerProof)
	if !isProofValid {
		t.Error("The signer proof is invalid for three public and three private attribute")
	}
}
