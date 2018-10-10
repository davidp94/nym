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

type witnessesS struct {
	wr *Curve.BIG
	wk []*Curve.BIG
	wm []*Curve.BIG
}

type witnessesV struct {
	wm []*Curve.BIG
	wt *Curve.BIG
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
func constructVerifierProofWitn(witnesses *witnessesV, params *Params, vk *VerificationKey, sig *Signature, privM []*Curve.BIG, t *Curve.BIG) *VerifierProof {
	p, g1, g2, hs := params.p, params.g1, params.g2, params.hs
	wm := witnesses.wm
	wt := witnesses.wt

	// witnesses commitments
	Aw := Curve.G2mul(g2, wt) // Aw = (wt * g2)
	Aw.Add(vk.alpha)          // Aw = (wt * g2) + alpha
	for i := range privM {
		Aw.Add(Curve.G2mul(vk.beta[i], wm[i])) // Aw = (wt * g2) + alpha + (wm[0] * beta[0]) + ... + (wm[i] * beta[i])
	}
	Bw := Curve.G1mul(sig.sig1, wt) // Bw = wt * h

	tmpSlice := []utils.Printable{g1, g2, vk.alpha, Aw, Bw}
	ca := make([]utils.Printable, len(tmpSlice)+len(hs)+len(vk.beta))
	i := copy(ca, tmpSlice)

	// can't use copy for those due to type difference (utils.Printable vs *Curve.ECP and *Curve.ECP2)
	for _, item := range hs {
		ca[i] = item
		i++
	}
	for _, item := range vk.beta {
		ca[i] = item
		i++
	}

	c := constructChallenge(ca)

	// responses
	rm := make([]*Curve.BIG, len(privM))
	for i := range privM {
		rm[i] = wm[i].Minus(Curve.Modmul(c, privM[i], p))
		rm[i] = rm[i].Plus(p)
		rm[i].Mod(p)
	}

	rt := wt.Minus(Curve.Modmul(c, t, p))
	rt = rt.Plus(p)
	rt.Mod(p)

	return &VerifierProof{
		c:  c,
		rm: rm,
		rt: rt,
	}
}

// modified version with additional arguments to remove randomness
// and allow comparison with python implementation
func showBlindSignatureT(t *Curve.BIG, witn *witnessesV, params *Params, vk *VerificationKey, sig *Signature, privM []*Curve.BIG) (*BlindShowMats, error) {
	kappa := Curve.G2mul(vk.g2, t)
	kappa.Add(vk.alpha)
	for i := range privM {
		kappa.Add(Curve.G2mul(vk.beta[i], privM[i]))
	}
	nu := Curve.G1mul(sig.sig1, t)
	verifierProof := constructVerifierProofWitn(witn, params, vk, sig, privM, t)
	return &BlindShowMats{
		kappa: kappa,
		nu:    nu,
		proof: verifierProof,
	}, nil
}

// modified version with additional arguments to remove randomness
// and allow comparison with python implementation
func constructSignerProofWitn(witnesses *witnessesS, params *Params, gamma *Curve.ECP, encs []*elgamal.Encryption, cm *Curve.ECP, k []*Curve.BIG, r *Curve.BIG, pubM []*Curve.BIG, privM []*Curve.BIG) (*SignerProof, error) {
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
func prepareBlindSignR(t *testing.T, r *Curve.BIG, ks []*Curve.BIG, witn *witnessesS, params *Params, gamma *Curve.ECP, pubM []*Curve.BIG, privM []*Curve.BIG) (*BlindSignMats, error) {
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

func TestCurveParameters(t *testing.T) {
	if Curve.CURVE_PAIRING_TYPE != Curve.BN {
		return
	}

	g1Hex := "032523648240000001ba344d80000000086121000000000013a700000000000012"
	g2Hex := "061a10bb519eb62feb8d8c7e8c61edb6a4648bbb4898bf0d91ee4224c803fb2b0516aaf9ba737833310aa78c5982aa5b1f4d746bae3784b70d8c34c1e7d54cf3021897a06baf93439a90e096698c822329bd0ae6bdbe09bd19f0e07891cd2b9a0ebb2b0e7c8b15268f6d4456f5f38d37b09006ffd739c9578a2d1aec6b3ace9b"
	ordHex := "2523648240000001BA344D8000000007FF9F800000000010A10000000000000D"

	// ASSUMES SHA512 implementation with truncating arguments to Bn.from_binary()
	hs0Hex := "030b211c72262e97252c2e65f87679f7109189b351e928c7e54400f9cf02c111cf"
	hs1Hex := "0318d6f0cefec6d21330d55ba82d288458e9b04c479a561a58d19a9683013b1209"
	hs2Hex := "030111c4221476c957cc0ff08ac9843f806c28e08aaec978d141001473d57d9f73"
	hs3Hex := "030c6655d20bdca4c62fee4c18f253c460877e23783b50f0f026571c944f869b4d"

	params, err := Setup(4)
	assert.Nil(t, err)
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

	hsP := []*Curve.ECP{
		ECPFromHex(t, hs0Hex),
		ECPFromHex(t, hs1Hex),
		ECPFromHex(t, hs2Hex),
		ECPFromHex(t, hs3Hex),
	}

	// depends on the implementation, need to update if it fails
	for i := range hsP {
		assert.True(t, hsP[i].Equals(hs[i]))
	}
}

func TestBasicOperations(t *testing.T) {
	if Curve.CURVE_PAIRING_TYPE != Curve.BN {
		return
	}

	xHex := "076501B5E73FA81B28FAB06EE3F6929E6AE4DB9461A49930C49EF1B28A625DD2"
	g1MulResHex := "02096d26612159d5339748b78c53000734df70a678f4d2ce389b422b076bf5996b"
	g2MulResHex := "13b24880cbd8053ce23d5cfc42070fff29cae3bbbecf2c5c519b6bb1574b9e3e20e01badca9cc9394b30ce9d63d293953572d0d2f75a02632dc0217ab6fa05f912e9eabbed9eeccc8679c782c26a11d7bb0656930fe5b7d3d4d67d3424b7afd4212cf71b70d1e2a01299342878e350c3d82e17a5a4370adc7b7076ed87dce6b7"

	xP := BIGFromHex(t, xHex)
	g1MulResExp := ECPFromHex(t, g1MulResHex)
	g2MulResExp := ECP2FromHex(t, g2MulResHex)

	// previous test already established correct curve parameters
	params, err := Setup(4)
	assert.Nil(t, err)
	g1, g2 := params.g1, params.g2

	g1MulRes := Curve.G1mul(g1, xP)
	assert.True(t, g1MulRes.Equals(g1MulResExp))

	g2MulRes := Curve.G2mul(g2, xP)
	assert.True(t, g2MulRes.Equals(g2MulResExp))
}

func TestPointcheval(t *testing.T) {
	if Curve.CURVE_PAIRING_TYPE != Curve.BN {
		return
	}

	xHex := "076501B5E73FA81B28FAB06EE3F6929E6AE4DB9461A49930C49EF1B28A625DD2"
	yHex := "0CE30F26C29ADBE06AE98D9B49DB3FF323C8100072298E9A58AC347E9BE59F36"
	mHex := "1D70206E93922A266B6F522CB1EC8AA72F908AC87EED1E43C641BFAF3C82AC32"
	hHex := "021c1dbf7bdc24be8d2b5c56d7a3162a9a1ef824134c3a95b6d306ecd8ce90c193"
	PointchevalSigHex := "020f43b06f6500c76423ec744b28dff1a4a3594256b585265d86e6c7d307c86cc5"

	x := BIGFromHex(t, xHex)
	m := BIGFromHex(t, mHex)
	y := BIGFromHex(t, yHex)
	h := ECPFromHex(t, hHex)
	PointchevalSigP := ECPFromHex(t, PointchevalSigHex)

	params, err := Setup(4)
	assert.Nil(t, err)
	g2, p := params.g2, params.p

	// simple Pointcheval-Sanders signature on single public attribute
	t1 := Curve.Modmul(y, m, p)
	K := t1.Plus(x)
	PointchevalSig := Curve.G1mul(h, K)
	assert.True(t, PointchevalSig.Equals(PointchevalSigP))

	vk := &VerificationKey{
		g2:    g2,
		alpha: Curve.G2mul(g2, x),
		beta:  []*Curve.ECP2{Curve.G2mul(g2, y)},
	}
	signature := &Signature{sig1: h, sig2: PointchevalSig}
	// ensure it actually verifies
	assert.True(t, Verify(params, vk, []*Curve.BIG{m}, signature))
}

func TestCoconut(t *testing.T) {
	if Curve.CURVE_PAIRING_TYPE != Curve.BN {
		return
	}

	// secret key components
	xHex := "076501B5E73FA81B28FAB06EE3F6929E6AE4DB9461A49930C49EF1B28A625DD2"
	y0Hex := "0CE30F26C29ADBE06AE98D9B49DB3FF323C8100072298E9A58AC347E9BE59F36"
	y1Hex := "09BD32C15ED60E7C9E5EC7FD2D3294D712DDC0AE510071D3AD9CE3DE0F1F23C1"
	y2Hex := "0CF37DAD7889F0959E571D79532CD1E3AE74BD2B26C78D68251EDB7685782B9E"
	y3Hex := "07712709AED9F065B553E08267EA9A5C75D0B4F62DE110569BF350E8BDC0F980"

	// messages to sign
	mPriv1Hex := "24ABEE7D59CA09122391B3ECCBEBE0FA79EB9954D0E9F139A2A6E129445F1208"
	mPriv2Hex := "1B4A6A9A72935D4D3CBCDEA5143480C543E9F3F0C91787605220BF54EC4E6078"
	mPub1Hex := "1D70206E93922A266B6F522CB1EC8AA72F908AC87EED1E43C641BFAF3C82AC32"
	mPub2Hex := "0F6EE88081A8A94677A8993F85245C30106B1A8E794496276B1452915F4BB708"

	// for ElGamal keypair
	dHex := "1CF5133799A1CB2A1A46DD3FA5CB1EA9069D022236747F1CCA77401A265CEA33"
	// for ElGamal encryptions
	k1Hex := "077CA2D8137CA54B12011E564BA9B4204ADECA64499D07EE02DE6420E8B058A8"
	k2Hex := "12B9BD2873FD1BA68D0B61A9B6840CA920C493D54CE85E8C2143C12F144C3B26"

	// for using in commitment
	rHex := "24338A5F29CAB6BD573F87D5E2E6DDCFFB55CDB55D03A40A828A061E0E9957CE"

	// witnesses for pi_s:
	wrHex := "1D7A898A391A664BAF3146F7ACA1FC0E954ED426ACD2D50146997A94053DCF6A"
	wk1Hex := "0AF5628DF706A6CF503237499F793ABBDF4379DE3EF2D3DE777F4AB32B3147BD"
	wk2Hex := "0E093B9EE3273CFB42C2765A0D78EF4EBD40126DC1703A921680EAA4CF50814D"
	wm1Hex := "1DA762D767AD63BD4226CC6E859FC376CA03A047E47B82AFE8574D93DF39B5BB"
	wm2Hex := "11A4B4BF934A3709F9E7A54324AACF0ED13BCAAA0CC2AD2791437363A64E404C"
	wm3Hex := "096EB6930E70DEE0ACC0093A23A3586217C20FD6FD1ECB9923B2EDCE288F961F"
	wm4Hex := "131CCECB6386CA3A773C898193116B76A2D6BD34D3BB4A7BC7143E494B7C69D9"

	// results of prepare_blind_sign
	cmHex := "030849eb631f18b4bf18eefea4bd434bd7008de9dfe0b3db450e96a4978aab666e"
	c1Priv1Hex := "0312caf23ffd7749590f883772beb13249afd6f6cb5cb6bd0fe8cc5a57276f0e49"
	c2Priv1Hex := "021478f7f12c65970096e684ddcfbd3f7092bb82d06e9cf4360d5fd539ffcc21bf"
	c1Priv2Hex := "03137f64f199fafc1db69884523acc2b47735cbe09dc48795cfa96ac3888f9e6a7"
	c2Priv2Hex := "02231d4f703805cb64e76cadfba3d85b40f05defd13ba6e9cce5db7ed94009f106"
	// pi_s:
	chSHex := "37CAEA1F7CFACC39C5767CCF43361D7AE9A4DE868D7C33E2BF0ACBA8005B3A80"
	rk1SHex := "1522885F58EDC52CA001192BD62E7C6B1540A871E3B811F1730218E28AC8E6BB"
	rk2SHex := "1D45583D9ED278D3CEE2641ACB5C5CC877848B56C3ADAA24D8B7D3D512CD26B5"
	rm1SHex := "1C38F72D4AACE4279B119EEC925A5616775789BEE084314734E8325F8CA9BE7B"
	rm2SHex := "0E51EFB8E526291EF16788F6AE310CC0D63F158C72DCE5218F7EE40720F4F55A"
	rrSHex := "1942DB548E26B6566145A8E881BD218F9C24A1A9F07F63C221312C04C7F22A8F"

	// blind signature
	hTildaHex := "030f4bdc378c5fcb44e5e3d2e41eec3f7756738f62eb5ba2e637d904a3f0b0ab49"
	sigC1TildaHex := "02088b6b1b249e922c4d1f27dfc46a2a02b4cf6ed3c3b308bfac4f9a3ea95f289b"
	sigC2TildaHex := "020ca5d0e1a6ed0c8f9401ccdf0abc9cbab630b2ae0e888e8c8a0d3c7c11b020c6"
	sig2Hex := "0223a3693156fab9fcc63096a567a99c9bc9276ea6c05f168c494ec6eb41ed650f"

	// witnesses for pi_v
	wm1VHex := "05E8CB173C636A190CC628803768833123A9FC54A92224D97155E87EF7E3F3C4"
	wm2VHex := "124052CD6EB215D98B20F343348E3898E65AC82A43AA57D0720311259D05D3DA"
	wtHex := "0E7BF9EAD25C09716291E864B99DD063EC911ABCD26CBF682DE9B7C4E95D126F"

	// results of show_blind_sign
	tHex := "0ADE8E2E5EC8806EC1B873B0F5735A9EB7FCA8D7DA3AC8D965487E0982C75F68"
	kappaHex := "2227bc5a1acd5b4edfc244460d0679361535c0ddc0d5d2759d0f9c1f9eea117f1a8a933e3d69ce785f5524133a208a9259cc119221cfe72c99da3eb2475f96a30b7da97c5575b8e10c476fdd3cf6c8dc7d57d17bfe825dda473e9c4c697f0d880ca413462a517b67b727d50653cafb5a55a5062b3f0b23bd757a511cc6c9bfa0"
	nuHex := "030b9a28caf7c58ba525011a0685388514a792aaa98edc74fb83e319960e0f3880"
	// pi_v
	chVHex := "F277CD97107F373EFE48A986FD735F8BE79DE39DF97E0A87AF31B1964643B3C9"
	rm1VHex := "1FFAB49038C79193C43C1BE7F98A7ECD9E2907A259234312C0838C0EE62F4C1B"
	rm2VHex := "18AAB72BE3BA10CCC46659ADEEF201BE1D0C8FCEB0D6F431478DB06786AF671F"
	rtHex := "0B32CD80C75C2D339E062F735A037B3571CC882D6CBAF7F858726252FE56B363"

	params, _ := Setup(4)
	g1, g2 := params.g1, params.g2

	pubM := recoverBIGSlice(t, mPub1Hex, mPub2Hex)
	privM := recoverBIGSlice(t, mPriv1Hex, mPriv2Hex)
	sk, vk := recoverKeys(t, g2, xHex, y0Hex, y1Hex, y2Hex, y3Hex)

	// elgamal keypair
	d := BIGFromHex(t, dHex)
	gamma := Curve.G1mul(g1, d)

	r := BIGFromHex(t, rHex)
	ks := recoverBIGSlice(t, k1Hex, k2Hex)

	wr := BIGFromHex(t, wrHex)
	wk := recoverBIGSlice(t, wk1Hex, wk2Hex)
	wm := recoverBIGSlice(t, wm1Hex, wm2Hex, wm3Hex, wm4Hex)
	witnesses := &witnessesS{wr, wk, wm}

	bsm, err := prepareBlindSignR(t, r, ks, witnesses, params, gamma, pubM, privM)
	assert.Nil(t, err)

	// expected:
	cmExp := ECPFromHex(t, cmHex)
	c1e1Exp := ECPFromHex(t, c1Priv1Hex)
	c2e1Exp := ECPFromHex(t, c2Priv1Hex)
	c1e2Exp := ECPFromHex(t, c1Priv2Hex)
	c2e2Exp := ECPFromHex(t, c2Priv2Hex)
	chSExp := BIGFromHex(t, chSHex)
	rkSExp := recoverBIGSlice(t, rk1SHex, rk2SHex)
	rmSExp := recoverBIGSlice(t, rm1SHex, rm2SHex)
	rrSExp := BIGFromHex(t, rrSHex)

	assert.True(t, bsm.cm.Equals(cmExp))
	assert.True(t, bsm.enc[0].C1().Equals(c1e1Exp))
	assert.True(t, bsm.enc[0].C2().Equals(c2e1Exp))
	assert.True(t, bsm.enc[1].C1().Equals(c1e2Exp))
	assert.True(t, bsm.enc[1].C2().Equals(c2e2Exp))

	assert.Zero(t, Curve.Comp(chSExp, bsm.proof.c))
	for i := range rkSExp {
		assert.Zero(t, Curve.Comp(rkSExp[i], bsm.proof.rk[i]))
	}
	for i := range rmSExp {
		assert.Zero(t, Curve.Comp(rmSExp[i], bsm.proof.rm[i]))
	}
	assert.Zero(t, Curve.Comp(rrSExp, bsm.proof.rr))

	blindedSig, err := BlindSign(params, sk, bsm, gamma, pubM)
	assert.Nil(t, err)

	// expected:
	blindSig1Exp := ECPFromHex(t, hTildaHex)
	blindSig2C1Exp := ECPFromHex(t, sigC1TildaHex)
	blindSig2C2Exp := ECPFromHex(t, sigC2TildaHex)

	assert.True(t, blindSig1Exp.Equals(blindedSig.sig1))
	assert.True(t, blindSig2C1Exp.Equals(blindedSig.sig2Tilda.C1()))
	assert.True(t, blindSig2C2Exp.Equals(blindedSig.sig2Tilda.C2()))

	sig := Unblind(params, blindedSig, d)

	sig2Exp := ECPFromHex(t, sig2Hex)
	assert.True(t, blindSig1Exp.Equals(sig.sig1))
	assert.True(t, sig2Exp.Equals(sig.sig2))

	tr := BIGFromHex(t, tHex)
	wmV := recoverBIGSlice(t, wm1VHex, wm2VHex)
	wt := BIGFromHex(t, wtHex)
	witnessesV := &witnessesV{wmV, wt}

	bsm2, err := showBlindSignatureT(tr, witnessesV, params, vk, sig, privM)
	assert.Nil(t, err)

	// expected:
	kappaExp := ECP2FromHex(t, kappaHex)
	nuExp := ECPFromHex(t, nuHex)
	chVExp := BIGFromHex(t, chVHex)
	rmVExp := recoverBIGSlice(t, rm1VHex, rm2VHex)
	rtExp := BIGFromHex(t, rtHex)

	assert.True(t, kappaExp.Equals(bsm2.kappa))
	assert.True(t, nuExp.Equals(bsm2.nu))
	assert.Zero(t, Curve.Comp(chVExp, bsm2.proof.c))
	for i := range rmVExp {
		assert.Zero(t, Curve.Comp(rmVExp[i], bsm2.proof.rm[i]))
	}
	assert.Zero(t, Curve.Comp(rtExp, bsm2.proof.rt))

	// finally for sanity checks ensure the credentials verify
	assert.True(t, BlindVerify(params, vk, sig, bsm2, pubM))
}
