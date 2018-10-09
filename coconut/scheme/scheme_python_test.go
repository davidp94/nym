// scheme_python_test.go - tests compatibility with Python implementation
// Copyright (C) 2018  Jedrzej Stuczynski.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package coconut

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BN254"
)

// todo: wait for George's fix for hashG1 to know which solution to choose
// todo: wait for Alberto's fix for threshold credentials to make tests for them

type witnesses struct {
	wr *Curve.BIG
	wk []*Curve.BIG
	wm []*Curve.BIG
}

func recoverKeys(t *testing.T, g2 *Curve.ECP2, xHex string, ysHex ...string) (*SecretKey, *VerificationKey) {
	x := BIGFromHex(t, xHex)
	y := make([]*Curve.BIG, len(ysHex))
	beta := make([]*Curve.ECP2, len(ysHex))
	for i, yi := range ysHex {
		y[i] = BIGFromHex(t, yi)
		beta[i] = Curve.G2mul(g2, y[i])
	}
	alpha := Curve.G2mul(g2, x)
	return &SecretKey{x, y}, &VerificationKey{g2, alpha, beta}
}

func recoverBIGSlice(t *testing.T, items ...string) []*Curve.BIG {
	slice := make([]*Curve.BIG, len(items))
	for i, item := range items {
		slice[i] = BIGFromHex(t, item)
	}
	return slice
}

func BIGFromHex(t *testing.T, hexStr string) *Curve.BIG {
	b, err := hex.DecodeString(hexStr)
	assert.Nil(t, err)
	return Curve.FromBytes(b)
}

func ECPFromHex(t *testing.T, hexStr string) *Curve.ECP {
	b, err := hex.DecodeString(hexStr)
	assert.Nil(t, err)
	return Curve.ECP_fromBytes(b)
}

func ECP2FromHex(t *testing.T, hexStr string) *Curve.ECP2 {
	b, err := hex.DecodeString(hexStr)
	assert.Nil(t, err)
	return Curve.ECP2_fromBytes(b)
}

// modified version with additional arguments to remove randomness
// and allow comparison with python implementation
func constructSignerProofWitn(witnesses *witnesses, params *Params, gamma *Curve.ECP, encs []*elgamal.Encryption, cm *Curve.ECP, k []*Curve.BIG, r *Curve.BIG, pubM []*Curve.BIG, privM []*Curve.BIG) (*SignerProof, error) {
	p, g1, g2, hs := params.p, params.g1, params.g2, params.hs
	attributes := append(privM, pubM...)
	wr := witnesses.wr
	wk := witnesses.wk
	wm := witnesses.wm

	b := make([]byte, utils.MB+1)
	cm.ToBytes(b, true)

	h, err := utils.HashBytesToG1(amcl.SHA256, b)
	if err != nil {
		return nil, err
	}

	// witnesses commitments
	Aw := make([]*Curve.ECP, len(wk))
	Bw := make([]*Curve.ECP, len(privM))
	var Cw *Curve.ECP

	for i := range wk {
		Aw[i] = Curve.G1mul(g1, wk[i]) // Aw[i] = (wk[i] * g1)
	}
	for i := range privM {
		Bw[i] = Curve.G1mul(h, wm[i])        // Bw[i] = (wm[i] * h)
		Bw[i].Add(Curve.G1mul(gamma, wk[i])) // Bw[i] = (wm[i] * h) + (wk[i] * gamma)
	}

	Cw = Curve.G1mul(g1, wr) // Cw = (wr * g1)
	for i := range attributes {
		Cw.Add(Curve.G1mul(hs[i], wm[i])) // Cw = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
	}

	tmpSlice := []utils.Printable{g1, g2, cm, h, Cw}
	ca := make([]utils.Printable, len(tmpSlice)+len(hs)+len(Aw)+len(Bw))
	i := copy(ca, tmpSlice)

	// can't use copy for those due to type difference (utils.Printable vs *Curve.ECP)
	for _, item := range hs {
		ca[i] = item
		i++
	}
	for _, item := range Aw {
		ca[i] = item
		i++
	}
	for _, item := range Bw {
		ca[i] = item
		i++
	}

	c := constructChallenge(ca)

	// responses
	rr := wr.Minus(Curve.Modmul(c, r, p))
	rr = rr.Plus(p)
	rr.Mod(p) // rr = (wr - c * r) % o

	rk := make([]*Curve.BIG, len(wk))
	for i := range wk {
		rk[i] = wk[i].Minus(Curve.Modmul(c, k[i], p))
		rk[i] = rk[i].Plus(p)
		rk[i].Mod(p) // rk[i] = (wk[i] - c * k[i]) % o
	}

	rm := make([]*Curve.BIG, len(wm))
	for i := range wm {
		rm[i] = wm[i].Minus(Curve.Modmul(c, attributes[i], p))
		rm[i] = rm[i].Plus(p)
		rm[i].Mod(p) // rm[i] = (wm[i] - c * attributes[i]) % o
	}

	return &SignerProof{
			c:  c,
			rr: rr,
			rk: rk,
			rm: rm},
		nil
}

// modified version with additional arguments to remove randomness
// and allow comparison with python implementation
func encryptK(G *bpgroup.BpGroup, k *Curve.BIG, gamma *Curve.ECP, m *Curve.BIG, h *Curve.ECP) (*elgamal.Encryption, *Curve.BIG) {
	g1 := G.Gen1()

	a := Curve.G1mul(g1, k)
	b := Curve.G1mul(gamma, k) // b = (k * gamma)
	b.Add(Curve.G1mul(h, m))   // b = (k * gamma) + (m * h)

	return elgamal.NewEncryptionFromPoints(a, b), k
}

// modified version with additional arguments to remove randomness
// and allow comparison with python implementation
func prepareBlindSign_r(t *testing.T, r *Curve.BIG, ks []*Curve.BIG, witn *witnesses, params *Params, gamma *Curve.ECP, pubM []*Curve.BIG, privM []*Curve.BIG) (*BlindSignMats, error) {
	G, g1, hs := params.G, params.g1, params.hs
	attributes := append(privM, pubM...)
	cm := Curve.G1mul(g1, r)

	cmElems := make([]*Curve.ECP, len(attributes))
	for i := range attributes {
		cmElems[i] = Curve.G1mul(hs[i], attributes[i])

	}
	for _, elem := range cmElems {
		cm.Add(elem)
	}

	b := make([]byte, utils.MB+1)
	cm.ToBytes(b, true)

	h, err := utils.HashBytesToG1(amcl.SHA256, b)
	if err != nil {
		return nil, err
	}

	encs := make([]*elgamal.Encryption, len(privM))
	// can't easily encrypt in parallel since random number generator object is shared between encryptions
	for i := range privM {
		c, _ := encryptK(G, ks[i], gamma, privM[i], h)
		encs[i] = c
	}

	signerProof, err := constructSignerProofWitn(witn, params, gamma, encs, cm, ks, r, pubM, privM)
	if err != nil {
		return nil, err
	}
	return &BlindSignMats{
		cm:    cm,
		enc:   encs,
		proof: signerProof,
	}, nil
}

// not testing for threshold signatures because at the time of writing this test, they are still broken in pyhon implementation
func TestCompareWithPython(t *testing.T) {
	if Curve.CURVE_PAIRING_TYPE != Curve.BN {
		return
	}
	g1Hex := "032523648240000001ba344d80000000086121000000000013a700000000000012"
	g2Hex := "061a10bb519eb62feb8d8c7e8c61edb6a4648bbb4898bf0d91ee4224c803fb2b0516aaf9ba737833310aa78c5982aa5b1f4d746bae3784b70d8c34c1e7d54cf3021897a06baf93439a90e096698c822329bd0ae6bdbe09bd19f0e07891cd2b9a0ebb2b0e7c8b15268f6d4456f5f38d37b09006ffd739c9578a2d1aec6b3ace9b"
	ordHex := "2523648240000001BA344D8000000007FF9F800000000010A10000000000000D"

	xHex := "076501B5E73FA81B28FAB06EE3F6929E6AE4DB9461A49930C49EF1B28A625DD2"
	y0Hex := "0CE30F26C29ADBE06AE98D9B49DB3FF323C8100072298E9A58AC347E9BE59F36"
	y1Hex := "09BD32C15ED60E7C9E5EC7FD2D3294D712DDC0AE510071D3AD9CE3DE0F1F23C1"
	y2Hex := "0CF37DAD7889F0959E571D79532CD1E3AE74BD2B26C78D68251EDB7685782B9E"
	y3Hex := "07712709AED9F065B553E08267EA9A5C75D0B4F62DE110569BF350E8BDC0F980"

	mPriv1Hex := "24ABEE7D59CA09122391B3ECCBEBE0FA79EB9954D0E9F139A2A6E129445F1208"
	mPriv2Hex := "1B4A6A9A72935D4D3CBCDEA5143480C543E9F3F0C91787605220BF54EC4E6078"
	mPub1Hex := "1D70206E93922A266B6F522CB1EC8AA72F908AC87EED1E43C641BFAF3C82AC32"
	mPub2Hex := "0F6EE88081A8A94677A8993F85245C30106B1A8E794496276B1452915F4BB708"

	g1resHex := "02096d26612159d5339748b78c53000734df70a678f4d2ce389b422b076bf5996b"
	XHex := "13b24880cbd8053ce23d5cfc42070fff29cae3bbbecf2c5c519b6bb1574b9e3e20e01badca9cc9394b30ce9d63d293953572d0d2f75a02632dc0217ab6fa05f912e9eabbed9eeccc8679c782c26a11d7bb0656930fe5b7d3d4d67d3424b7afd4212cf71b70d1e2a01299342878e350c3d82e17a5a4370adc7b7076ed87dce6b7"

	hHex := "021c1dbf7bdc24be8d2b5c56d7a3162a9a1ef824134c3a95b6d306ecd8ce90c193"
	PointchevalSigHex := "020f43b06f6500c76423ec744b28dff1a4a3594256b585265d86e6c7d307c86cc5"

	// for ElGamal keypair
	dHex := "1CF5133799A1CB2A1A46DD3FA5CB1EA9069D022236747F1CCA77401A265CEA33"
	// for using in commitment
	rHex := "24338A5F29CAB6BD573F87D5E2E6DDCFFB55CDB55D03A40A828A061E0E9957CE"

	// ASSUMES SHA512 implementation with truncating arguments to Bn.from_binary()
	hs0 := "030b211c72262e97252c2e65f87679f7109189b351e928c7e54400f9cf02c111cf"
	hs1 := "0318d6f0cefec6d21330d55ba82d288458e9b04c479a561a58d19a9683013b1209"
	hs2 := "030111c4221476c957cc0ff08ac9843f806c28e08aaec978d141001473d57d9f73"
	hs3 := "030c6655d20bdca4c62fee4c18f253c460877e23783b50f0f026571c944f869b4d"

	// for ElGamal encryptions
	k1Hex := "077CA2D8137CA54B12011E564BA9B4204ADECA64499D07EE02DE6420E8B058A8"
	k2Hex := "12B9BD2873FD1BA68D0B61A9B6840CA920C493D54CE85E8C2143C12F144C3B26"

	// witnesses:
	wrHex := "1D7A898A391A664BAF3146F7ACA1FC0E954ED426ACD2D50146997A94053DCF6A"
	wk1Hex := "0AF5628DF706A6CF503237499F793ABBDF4379DE3EF2D3DE777F4AB32B3147BD"
	wk2Hex := "0E093B9EE3273CFB42C2765A0D78EF4EBD40126DC1703A921680EAA4CF50814D"
	wm1Hex := "1DA762D767AD63BD4226CC6E859FC376CA03A047E47B82AFE8574D93DF39B5BB"
	wm2Hex := "11A4B4BF934A3709F9E7A54324AACF0ED13BCAAA0CC2AD2791437363A64E404C"
	wm3Hex := "096EB6930E70DEE0ACC0093A23A3586217C20FD6FD1ECB9923B2EDCE288F961F"
	wm4Hex := "131CCECB6386CA3A773C898193116B76A2D6BD34D3BB4A7BC7143E494B7C69D9"

	cmHex := "030849eb631f18b4bf18eefea4bd434bd7008de9dfe0b3db450e96a4978aab666e"
	c1Priv1Hex := "0312caf23ffd7749590f883772beb13249afd6f6cb5cb6bd0fe8cc5a57276f0e49"
	c2Priv1Hex := "021478f7f12c65970096e684ddcfbd3f7092bb82d06e9cf4360d5fd539ffcc21bf"
	c1Priv2Hex := "03137f64f199fafc1db69884523acc2b47735cbe09dc48795cfa96ac3888f9e6a7"
	c2Priv2Hex := "02231d4f703805cb64e76cadfba3d85b40f05defd13ba6e9cce5db7ed94009f106"
	// pi_s:
	chHex := "37CAEA1F7CFACC39C5767CCF43361D7AE9A4DE868D7C33E2BF0ACBA8005B3A80"
	rk1Hex := "1522885F58EDC52CA001192BD62E7C6B1540A871E3B811F1730218E28AC8E6BB"
	rk2Hex := "1D45583D9ED278D3CEE2641ACB5C5CC877848B56C3ADAA24D8B7D3D512CD26B5"
	rm1Hex := "1C38F72D4AACE4279B119EEC925A5616775789BEE084314734E8325F8CA9BE7B"
	rm2Hex := "0E51EFB8E526291EF16788F6AE310CC0D63F158C72DCE5218F7EE40720F4F55A"
	rrHex := "1942DB548E26B6566145A8E881BD218F9C24A1A9F07F63C221312C04C7F22A8F"

	params, _ := Setup(4)
	g1, g2, p, hs := params.g1, params.g2, params.p, params.hs

	g1P := ECPFromHex(t, g1Hex)
	assert.True(t, g1.Equals(g1P))                    // ensure they actually represent same point on the curve
	assert.Equal(t, g1Hex, utils.ToCoconutString(g1)) // and that they have same string representation

	g2P := ECP2FromHex(t, g2Hex)
	assert.True(t, g2.Equals(g2P))                    // ensure they actually represent same point on the curve
	assert.Equal(t, g2Hex, utils.ToCoconutString(g2)) // and that they have same string representation

	ordP := BIGFromHex(t, ordHex)
	assert.Zero(t, Curve.Comp(ordP, p))               // ensure they actually represent same value
	assert.Equal(t, ordHex, utils.ToCoconutString(p)) // and that they have same string representation

	xP := BIGFromHex(t, xHex)
	g1resP := ECPFromHex(t, g1resHex)
	XP := ECP2FromHex(t, XHex)

	// we've already established (with previous tests) that we can recover EC points and BN from hex so we don't test for that
	g1res := Curve.G1mul(g1, xP)
	assert.True(t, g1res.Equals(g1resP))

	X := Curve.G2mul(g2, xP)
	assert.True(t, X.Equals(XP))

	m := BIGFromHex(t, mPub1Hex)
	y0 := BIGFromHex(t, y0Hex)
	hP := ECPFromHex(t, hHex)
	PointchevalSigP := ECPFromHex(t, PointchevalSigHex)

	// simple Pointcheval-Sanders signature on single public attribute
	t1 := Curve.Modmul(y0, m, p)
	K := t1.Plus(xP)
	PointchevalSig := Curve.G1mul(hP, K)
	assert.True(t, PointchevalSig.Equals(PointchevalSigP))

	vk := &VerificationKey{g2: g2, alpha: X, beta: []*Curve.ECP2{Curve.G2mul(g2, y0)}}
	signature := &Signature{sig1: hP, sig2: PointchevalSig}
	// ensure it actually verifies
	assert.True(t, Verify(params, vk, []*Curve.BIG{m}, signature))

	// now check an actual coconut signature on 2 private and 2 public attributes

	// get messages
	pubM := recoverBIGSlice(t, mPub1Hex, mPub2Hex)
	privM := recoverBIGSlice(t, mPriv1Hex, mPriv2Hex)

	skFull, vkFull := recoverKeys(t, g2, xHex, y0Hex, y1Hex, y2Hex, y3Hex)

	hsP := []*Curve.ECP{
		ECPFromHex(t, hs0),
		ECPFromHex(t, hs1),
		ECPFromHex(t, hs2),
		ECPFromHex(t, hs3),
	}

	for i := range hsP {
		assert.True(t, hsP[i].Equals(hs[i])) // dependant on the implementation, need to update if it fails
	}

	// elgamal keypair
	d := BIGFromHex(t, dHex)
	gamma := Curve.G1mul(g1, d)
	r := BIGFromHex(t, rHex)
	ks := recoverBIGSlice(t, k1Hex, k2Hex)
	wr := BIGFromHex(t, wrHex)
	wk := recoverBIGSlice(t, wk1Hex, wk2Hex)
	wm := recoverBIGSlice(t, wm1Hex, wm2Hex, wm3Hex, wm4Hex)
	witnesses := &witnesses{wr, wk, wm}

	bsm, err := prepareBlindSign_r(t, r, ks, witnesses, params, gamma, pubM, privM)
	assert.Nil(t, err)

	// expected:
	cmExp := ECPFromHex(t, cmHex)
	c1e1 := ECPFromHex(t, c1Priv1Hex)
	c2e1 := ECPFromHex(t, c2Priv1Hex)
	c1e2 := ECPFromHex(t, c1Priv2Hex)
	c2e2 := ECPFromHex(t, c2Priv2Hex)
	ch := BIGFromHex(t, chHex)
	rk := recoverBIGSlice(t, rk1Hex, rk2Hex)
	rm := recoverBIGSlice(t, rm1Hex, rm2Hex)
	rr := BIGFromHex(t, rrHex)

	assert.True(t, bsm.cm.Equals(cmExp))
	assert.True(t, bsm.enc[0].C1().Equals(c1e1))
	assert.True(t, bsm.enc[0].C2().Equals(c2e1))
	assert.True(t, bsm.enc[1].C1().Equals(c1e2))
	assert.True(t, bsm.enc[1].C2().Equals(c2e2))

	assert.Zero(t, Curve.Comp(ch, bsm.proof.c))
	for i := range rk {
		assert.Zero(t, Curve.Comp(rk[i], bsm.proof.rk[i]))
	}
	for i := range rm {
		assert.Zero(t, Curve.Comp(rm[i], bsm.proof.rm[i]))
	}
	assert.Zero(t, Curve.Comp(rr, bsm.proof.rr))

	_ = skFull
	_ = vkFull
}
