// currently this version does not include threshold credentials
// those will be added in further iteration

// todos:
// modify sk to be in form of (x, [ys])
// modify vk to be in form of (g2, x, [ys])
// introduce 'assertions' in older functions
// threshold
package coconut

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

type Signature struct {
	sig1 *BLS381.ECP
	sig2 *BLS381.ECP
}

type BlindedSignature struct {
	sig1      *BLS381.ECP
	sig2Tilda *elgamal.ElGamalEncryption
}

type Params struct {
	G  *bpgroup.BpGroup
	Hs []*BLS381.ECP
}

type BlindSignMats struct {
	cm    *BLS381.ECP
	enc   []*elgamal.ElGamalEncryption
	proof *SignerProof
}

type BlindShowMats struct {
	kappa *BLS381.ECP2
	nu    *BLS381.ECP
	proof *VerifierProof
}

// q is the maximum number of attributes that can be embedded in the credential
func Setup(q int) *Params {
	hs := make([]*BLS381.ECP, q)
	for i := 0; i < q; i++ {
		hi, err := utils.HashStringToG1(amcl.SHA256, fmt.Sprintf("h%d", i))
		if err != nil {
			panic(err)
		}
		hs[i] = hi
	}
	G := bpgroup.New()
	return &Params{G, hs}
}

// todo: to be replaced by generation of keys threshold signature (by a TTP)
// right now it is keygen as if performed by a single isolated entity
func Keygen(params *Params) ([]*BLS381.BIG, []*BLS381.ECP2) {
	q := len(params.Hs) // todo: verify
	G := params.G

	sk := make([]*BLS381.BIG, q+1)
	vk := make([]*BLS381.ECP2, q+2)
	vk[0] = G.Gen2

	var wg sync.WaitGroup
	wg.Add(q + 1)

	for i := 0; i < q+1; i++ {
		sk[i] = BLS381.Randomnum(G.Ord, G.Rng) // we can't easily parallelize it due to shared resource and little performance gain
	}

	for i := 0; i < q+1; i++ {
		go func(i int) {
			vk[i+1] = BLS381.G2mul(G.Gen2, sk[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	return sk, vk
}

// this is a very temporary solution that will be modified once private attributes are introduced
// the sole point of it is to have some deterministic attribute dependant h value
func getBaseFromAttributes(public_m []*BLS381.BIG) *BLS381.ECP {
	s := make([]string, len(public_m))
	for i := range public_m {
		s[i] = public_m[i].ToString()
	}
	h, err := utils.HashStringToG1(amcl.SHA256, strings.Join(s, ","))
	if err != nil {
		panic(err)
	}
	return h
}

// at this iteration, only public attributes are considered
func Sign(params *Params, sk []*BLS381.BIG, public_m []*BLS381.BIG) *Signature {
	// todo: also consider parallelization - need to check overhead of Modmul whether it is worth (for comparison G1mul or G2mul are rather expensive operations)
	// todo later on: decide on concrete generation of h
	// todo: deal with case when len(sk) != len(public_m) + 1 - throw some error
	G := params.G
	h := getBaseFromAttributes(public_m)
	// for some reason in js version i used DBIG? check why
	// also took copy and then mod of all BIGs
	K := BLS381.NewBIGcopy(sk[0]) // K = x0
	for i := 0; i < len(public_m); i++ {
		tmp := BLS381.Modmul(sk[i+1], public_m[i], G.Ord) // (xi * ai)
		K = K.Plus(tmp)                                   // K = x0 + (x1 * a1) + ...
	}
	sig := BLS381.G1mul(h, K) // sig = h^(x0 + (x1 * a1) + ... )

	return &Signature{h, sig}
}

func PrepareBlindSign(params *Params, gamma *BLS381.ECP, public_m []*BLS381.BIG, private_m []*BLS381.BIG) (*BlindSignMats, error) {
	G := params.G
	if len(private_m) == 0 {
		return nil, errors.New("No private attributes to sign")
	}
	attributes := append(private_m, public_m...)
	if len(attributes) > len(params.Hs) {
		return nil, errors.New("Too many attributes to sign")
	}

	r := BLS381.Randomnum(G.Ord, G.Rng)
	cm := BLS381.G1mul(params.G.Gen1, r)
	for i := range attributes {
		cm.Add(BLS381.G1mul(params.Hs[i], attributes[i]))
	}
	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
	if err != nil {
		return nil, err
	}

	encs := make([]*elgamal.ElGamalEncryption, len(private_m))
	ks := make([]*BLS381.BIG, len(private_m))
	for i := range private_m {
		c, k := elgamal.Encrypt(G, gamma, private_m[i], h)
		encs[i] = c
		ks[i] = k
	}

	signerProof, err := ConstructSignerProof(params, gamma, encs, cm, ks, r, public_m, private_m)
	if err != nil {
		return nil, err
	}
	return &BlindSignMats{
		cm:    cm,
		enc:   encs,
		proof: signerProof,
	}, nil
}

// todo: update for threshold credentials
func BlindSign(params *Params, sk []*BLS381.BIG, blindSignMats *BlindSignMats, gamma *BLS381.ECP, public_m []*BLS381.BIG) (*BlindedSignature, error) {
	if len(blindSignMats.enc)+len(public_m) > len(params.Hs) {
		return nil, errors.New("Too many attributes to sign")
	}
	if !VerifySignerProof(params, gamma, blindSignMats.enc, blindSignMats.cm, blindSignMats.proof) {
		return nil, errors.New("Failed to verify the proof")
	}
	h, err := utils.HashStringToG1(amcl.SHA256, blindSignMats.cm.ToString())
	if err != nil {
		return nil, err
	}

	t1 := make([]*BLS381.ECP, len(public_m))
	for i := range public_m {
		t1[i] = BLS381.G1mul(h, public_m[i])
	}

	t2 := BLS381.G1mul(blindSignMats.enc[0].A, sk[1])
	for i := 1; i < len(blindSignMats.enc); i++ {
		t2.Add(BLS381.G1mul(blindSignMats.enc[i].A, sk[i+1]))
	}

	t3 := BLS381.G1mul(h, sk[0])
	tmpSlice := make([]*BLS381.ECP, len(blindSignMats.enc))
	for i := range blindSignMats.enc {
		tmpSlice[i] = blindSignMats.enc[i].B
	}
	tmpSlice = append(tmpSlice, t1...)

	// tmpslice: all B + t1
	for i := 1; i < len(sk); i++ {
		t3.Add(BLS381.G1mul(tmpSlice[i-1], sk[i]))
	}

	return &BlindedSignature{
		sig1: h,
		sig2Tilda: &elgamal.ElGamalEncryption{
			A: t2,
			B: t3,
		},
	}, nil
}

func Unblind(params *Params, blindedSignature *BlindedSignature, d *BLS381.BIG) *Signature {
	sig2 := elgamal.Decrypt(params.G, d, blindedSignature.sig2Tilda)
	return &Signature{
		sig1: blindedSignature.sig1,
		sig2: sig2,
	}
}

// similarly to Sign, this iteration only considers public attributes
func Verify(params *Params, vk []*BLS381.ECP2, public_m []*BLS381.BIG, sig *Signature) bool {
	// todo: same concerns as with Sign
	// h := getBaseFromAttributes(public_m)
	G := params.G
	// ensure G.Gen2 == vk[0] ?

	K := BLS381.NewECP2()
	K.Copy(vk[1]) // K = X0
	tmp := make([]*BLS381.ECP2, len(public_m))
	var wg sync.WaitGroup
	wg.Add(len(public_m))
	for i := 0; i < len(public_m); i++ {
		go func(i int) {
			tmp[i] = BLS381.G2mul(vk[i+2], public_m[i]) // (Yi * ai)
			wg.Done()
		}(i)
	}
	wg.Wait()
	for i := 0; i < len(public_m); i++ {
		K.Add(tmp[i]) // K = X0 + (Y1 * a1) + ...
	}

	wg.Add(2)
	var Gt1 *BLS381.FP12
	var Gt2 *BLS381.FP12

	go func() {
		Gt1 = G.Pair(sig.sig1, K)
		wg.Done()
	}()
	go func() {
		Gt2 = G.Pair(sig.sig2, vk[0])
		wg.Done()
	}()
	wg.Wait()
	// Gt1 := G.Pair(sig.sig1, K)
	// Gt2 := G.Pair(sig.sig2, vk[0])
	return !sig.sig1.Is_infinity() && Gt1.Equals(Gt2)
}

// CURRENTLY IGNORES PROOFS OF KAPPA AND NU
func ShowBlindSignature(params *Params, vk []*BLS381.ECP2, sig *Signature, private_m []*BLS381.BIG) (*BlindShowMats, error) {
	G := params.G
	if len(private_m) == 0 || len(private_m) > (len(vk)-2) {
		return nil, errors.New("Invalid number of private attributes provided")
	}

	t := BLS381.Randomnum(G.Ord, G.Rng)
	kappa := BLS381.G2mul(vk[0], t)
	kappa.Add(vk[1])
	for i := range private_m {
		kappa.Add(BLS381.G2mul(vk[i+2], private_m[i]))
	}
	nu := BLS381.G1mul(sig.sig1, t)

	verifierProof, err := ConstructVerifierProof(params, vk, sig, private_m, t)
	if err != nil {
		return nil, err
	}
	return &BlindShowMats{
		kappa: kappa,
		nu:    nu,
		proof: verifierProof,
	}, nil
}

// CURRENTLY IGNORES PROOFS OF KAPPA AND NU
func BlindVerify(params *Params, vk []*BLS381.ECP2, sig *Signature, showMats *BlindShowMats, public_m []*BLS381.BIG) bool {
	// todo: length assertion for proof
	// once proofs are introduced, will be taken directly from the proof
	privateLen := len(showMats.proof.rm)
	if len(public_m)+privateLen > len(vk)-2 {
		return false
	}
	if !VerifyVerifierProof(params, vk, sig, showMats) {
		return false
	}

	var aggr *BLS381.ECP2
	if len(public_m) == 0 {
		aggr = BLS381.NewECP2() // new point is at infinity
	} else {
		aggr = BLS381.G2mul(vk[2+privateLen], public_m[0]) // guaranteed to have at least 1 element
		for i := 1; i < len(public_m); i++ {
			aggr.Add(BLS381.G2mul(vk[i+2+privateLen], public_m[i]))
		}
	}
	t1 := BLS381.NewECP2()
	t1.Copy(showMats.kappa)
	t1.Add(aggr)

	t2 := BLS381.NewECP()
	t2.Copy(sig.sig2)
	t2.Add(showMats.nu)

	Gt1 := params.G.Pair(sig.sig1, t1)
	Gt2 := params.G.Pair(t2, vk[0])

	return !sig.sig1.Is_infinity() && Gt1.Equals(Gt2)
}

func Randomize(params *Params, sig *Signature) *Signature {
	G := params.G
	var wg sync.WaitGroup
	var rSig Signature
	t := BLS381.Randomnum(G.Ord, G.Rng)
	wg.Add(2)
	go func() {
		rSig.sig1 = BLS381.G1mul(sig.sig1, t)
		wg.Done()
	}()
	go func() {
		rSig.sig2 = BLS381.G1mul(sig.sig2, t)
		wg.Done()
	}()
	wg.Wait()
	return &rSig
}

// todo: special case for threshold
func AggregateVerificationKeys(params *Params, vks [][]*BLS381.ECP2) []*BLS381.ECP2 {
	avk := []*BLS381.ECP2{vks[0][0]} // the first element is always gen of G2
	// and since it is a pointer to constant element, it can be shared among multiple instances

	// again, consider parallelization for both loops?
	for i := 1; i < len(vks[0]); i++ {
		tmp := BLS381.NewECP2()
		tmp.Copy(vks[0][i])
		avk = append(avk, tmp)
	}

	for i := 1; i < len(vks); i++ { // we already copied values from first set of keys
		for j := 1; j < len(avk); j++ { // we ignore first element (the generator)
			avk[j].Add(vks[i][j])
		}
	}

	return avk
}

// todo: special case for threshold
func AggregateSignatures(params *Params, sigs []*Signature) *Signature {
	// in principle there's no need to copy sig1 as it's the same among all signatures and we can reuse one of the pointers
	sig2Cp := BLS381.NewECP()
	sig2Cp.Copy(sigs[0].sig2)

	for i := 1; i < len(sigs); i++ {
		sig2Cp.Add(sigs[i].sig2)
	}

	return &Signature{
		sig1: sigs[0].sig1,
		sig2: sig2Cp,
	}
}
