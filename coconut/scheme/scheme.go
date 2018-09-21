// todos:
// allow for q being arbitrary larger than number of signed parameters
// parallelization

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

type SecretKey struct {
	x *BLS381.BIG
	y []*BLS381.BIG
}

type VerificationKey struct {
	g2    *BLS381.ECP2
	alpha *BLS381.ECP2
	beta  []*BLS381.ECP2
}

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
	hs []*BLS381.ECP
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

type PolynomialPoints struct {
	xs []*BLS381.BIG
}

var (
	ErrSetupParams             = errors.New("Can't generate params for less than 1 attribute")
	ErrSignParams              = errors.New("Invalid attributes/secret key provided")
	ErrKeygenParams            = errors.New("Can't generate keys for less than 1 attribute")
	ErrTTPKeygenParams         = errors.New("Invalid set of parameters provided to keygen")
	ErrPrepareBlindSignParams  = errors.New("Too many attributes to sign")
	ErrPrepareBlindSignPrivate = errors.New("No private attributes to sign")
	ErrBlindSignAttr           = errors.New("Too many attributes to sign")
	ErrBlindSignProof          = errors.New("Failed to verify the proof")
	ErrShowBlindAttr           = errors.New("Invalid attributes provided")
)

// q is the maximum number of attributes that can be embedded in the credential
func Setup(q int) (*Params, error) {
	if q < 1 {
		return nil, ErrSetupParams
	}
	var wg sync.WaitGroup
	wg.Add(q)
	hs := make([]*BLS381.ECP, q)
	for i := 0; i < q; i++ {
		go func(i int) {
			hi, err := utils.HashStringToG1(amcl.SHA256, fmt.Sprintf("h%d", i))
			if err != nil {
				panic(err)
			}
			hs[i] = hi
			wg.Done()
		}(i)
	}
	wg.Wait()
	G := bpgroup.New()
	return &Params{G, hs}, nil
}

// This keygen does not support threshold credentials, all values is secret key are purely random with no correlation
func Keygen(params *Params) (*SecretKey, *VerificationKey, error) {
	q := len(params.hs)
	if q < 1 {
		return nil, nil, ErrKeygenParams
	}
	G := params.G

	x := BLS381.Randomnum(G.Ord, G.Rng)
	y := make([]*BLS381.BIG, q)
	sk := &SecretKey{x: x, y: y}

	for i := 0; i < q; i++ {
		y[i] = BLS381.Randomnum(G.Ord, G.Rng) // we can't easily parallelize it due to shared resource and little performance gain
	}

	alpha := BLS381.G2mul(G.Gen2, x)
	beta := make([]*BLS381.ECP2, q)
	vk := &VerificationKey{g2: G.Gen2, alpha: alpha, beta: beta}

	var wg sync.WaitGroup
	wg.Add(q)

	for i := 0; i < q; i++ {
		go func(i int) {
			beta[i] = BLS381.G2mul(G.Gen2, y[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	return sk, vk, nil
}

// t - treshold parameter
// n - total number of authorities
func TTPKeygen(params *Params, t int, n int) ([]*SecretKey, []*VerificationKey, error) {
	q := len(params.hs)
	G := params.G
	if n < t || t <= 0 || q <= 0 {
		return nil, nil, ErrTTPKeygenParams
	}

	// polynomials generation
	v := make([]*BLS381.BIG, t)
	for i := range v {
		v[i] = BLS381.Randomnum(G.Ord, G.Rng)
	}

	w := make([][]*BLS381.BIG, q)
	for i := range w {
		w[i] = make([]*BLS381.BIG, t)
		for j := range w[i] {
			w[i][j] = BLS381.Randomnum(G.Ord, G.Rng)
		}
	}

	var wg sync.WaitGroup
	wg.Add(n)
	// secret keys
	sks := make([]*SecretKey, n)
	// we can use any is now, rather than 1,2...,n; might be useful if we have some authorities ids?
	for i := 1; i < n+1; i++ {
		go func(i int) {
			iBIG := BLS381.NewBIGint(i)
			x := utils.PolyEval(v, iBIG, G.Ord)
			ys := make([]*BLS381.BIG, q)
			for j, wj := range w {
				ys[j] = utils.PolyEval(wj, iBIG, G.Ord)
			}
			sks[i-1] = &SecretKey{x: x, y: ys}
			wg.Done()
		}(i)
	}
	wg.Wait()
	wg.Add(n) // no point in overdoing it by assigning new goroutine to each G2mul (it's unlikely we'd have enough CPU cores to make use of that)

	// verification keys
	vks := make([]*VerificationKey, n)
	for i := range sks {
		go func(i int) {
			alpha := BLS381.G2mul(G.Gen2, sks[i].x)
			beta := make([]*BLS381.ECP2, q)
			for j, yj := range sks[i].y {
				beta[j] = BLS381.G2mul(G.Gen2, yj)
			}
			vks[i] = &VerificationKey{g2: G.Gen2, alpha: alpha, beta: beta}
			wg.Done()
		}(i)
	}
	wg.Wait()
	return sks, vks, nil
}

// generates the base h from public attributes; only used for sign (NOT blind sign)
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

// creates a credential on only public attributes
func Sign(params *Params, sk *SecretKey, public_m []*BLS381.BIG) (*Signature, error) {
	if len(public_m) != len(sk.y) {
		return nil, ErrSignParams
	}
	G := params.G
	h := getBaseFromAttributes(public_m)

	K := BLS381.NewBIGcopy(sk.x) // K = x
	for i := 0; i < len(public_m); i++ {
		tmp := BLS381.Modmul(sk.y[i], public_m[i], G.Ord) // (yi * ai)
		K = K.Plus(tmp)                                   // K = x + (y1 * a1) + ...
	}
	sig := BLS381.G1mul(h, K) // sig = h^(x + (y1 * a1) + ... )

	return &Signature{h, sig}, nil
}

func PrepareBlindSign(params *Params, gamma *BLS381.ECP, public_m []*BLS381.BIG, private_m []*BLS381.BIG) (*BlindSignMats, error) {
	G := params.G
	if len(private_m) <= 0 {
		return nil, ErrPrepareBlindSignPrivate
	}
	attributes := append(private_m, public_m...)
	if len(attributes) > len(params.hs) {
		return nil, ErrPrepareBlindSignParams
	}

	r := BLS381.Randomnum(G.Ord, G.Rng)

	cm := BLS381.G1mul(params.G.Gen1, r)

	cmElems := make([]*BLS381.ECP, len(attributes))
	var wg sync.WaitGroup
	wg.Add(len(attributes))
	for i := range attributes {
		go func(i int) {
			cmElems[i] = BLS381.G1mul(params.hs[i], attributes[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
	for _, elem := range cmElems {
		cm.Add(elem)
	}

	// cm.Add(BLS381.G1mul(params.hs[i], attributes[i]))

	h, err := utils.HashStringToG1(amcl.SHA256, cm.ToString())
	if err != nil {
		return nil, err
	}

	encs := make([]*elgamal.ElGamalEncryption, len(private_m))
	ks := make([]*BLS381.BIG, len(private_m))
	for i := range private_m { // can't easily encrypt in parallel since random number generator object is shared between encryptions
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

func BlindSign(params *Params, sk *SecretKey, blindSignMats *BlindSignMats, gamma *BLS381.ECP, public_m []*BLS381.BIG) (*BlindedSignature, error) {
	if len(blindSignMats.enc)+len(public_m) > len(params.hs) {
		return nil, ErrBlindSignAttr
	}
	if !VerifySignerProof(params, gamma, blindSignMats.enc, blindSignMats.cm, blindSignMats.proof) {
		return nil, ErrBlindSignProof
	}
	h, err := utils.HashStringToG1(amcl.SHA256, blindSignMats.cm.ToString())
	if err != nil {
		return nil, err
	}

	t1 := make([]*BLS381.ECP, len(public_m))
	for i := range public_m {
		t1[i] = BLS381.G1mul(h, public_m[i])
	}

	t2 := BLS381.G1mul(blindSignMats.enc[0].A, sk.y[0])
	for i := 1; i < len(blindSignMats.enc); i++ {
		t2.Add(BLS381.G1mul(blindSignMats.enc[i].A, sk.y[i]))
	}

	t3 := BLS381.G1mul(h, sk.x)
	tmpSlice := make([]*BLS381.ECP, len(blindSignMats.enc))
	for i := range blindSignMats.enc {
		tmpSlice[i] = blindSignMats.enc[i].B
	}
	tmpSlice = append(tmpSlice, t1...)

	// tmpslice: all B + t1
	for i := range sk.y {
		t3.Add(BLS381.G1mul(tmpSlice[i], sk.y[i]))
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

// works on public attributes or when all private attributes have been revealed
func Verify(params *Params, vk *VerificationKey, public_m []*BLS381.BIG, sig *Signature) bool {
	if len(public_m) != len(vk.beta) {
		return false
	}
	G := params.G

	K := BLS381.NewECP2()
	K.Copy(vk.alpha) // K = X
	tmp := make([]*BLS381.ECP2, len(public_m))

	var wg sync.WaitGroup
	wg.Add(len(public_m))
	for i := 0; i < len(public_m); i++ {
		go func(i int) {
			tmp[i] = BLS381.G2mul(vk.beta[i], public_m[i]) // (Yi * ai)
			wg.Done()
		}(i)
	}
	wg.Wait()
	for i := 0; i < len(public_m); i++ {
		K.Add(tmp[i]) // K = X + (Y1 * a1) + ...
	}

	wg.Add(2)
	var Gt1 *BLS381.FP12
	var Gt2 *BLS381.FP12

	go func() {
		Gt1 = G.Pair(sig.sig1, K)
		wg.Done()
	}()
	go func() {
		Gt2 = G.Pair(sig.sig2, vk.g2)
		wg.Done()
	}()
	wg.Wait()

	return !sig.sig1.Is_infinity() && Gt1.Equals(Gt2)
}

func ShowBlindSignature(params *Params, vk *VerificationKey, sig *Signature, private_m []*BLS381.BIG) (*BlindShowMats, error) {
	G := params.G
	if len(private_m) <= 0 || len(private_m) > len(vk.beta) {
		return nil, ErrShowBlindAttr
	}

	t := BLS381.Randomnum(G.Ord, G.Rng)
	kappa := BLS381.G2mul(vk.g2, t)
	kappa.Add(vk.alpha)
	for i := range private_m {
		kappa.Add(BLS381.G2mul(vk.beta[i], private_m[i]))
	}
	nu := BLS381.G1mul(sig.sig1, t)

	verifierProof := ConstructVerifierProof(params, vk, sig, private_m, t)

	return &BlindShowMats{
		kappa: kappa,
		nu:    nu,
		proof: verifierProof,
	}, nil
}

func BlindVerify(params *Params, vk *VerificationKey, sig *Signature, showMats *BlindShowMats, public_m []*BLS381.BIG) bool {
	privateLen := len(showMats.proof.rm)
	if len(public_m)+privateLen > len(vk.beta) {
		return false
	}
	if !VerifyVerifierProof(params, vk, sig, showMats) {
		return false
	}

	var aggr *BLS381.ECP2
	if len(public_m) <= 0 {
		aggr = BLS381.NewECP2() // new point is at infinity
	} else {
		aggr = BLS381.G2mul(vk.beta[privateLen], public_m[0]) // guaranteed to have at least 1 element
		for i := 1; i < len(public_m); i++ {
			aggr.Add(BLS381.G2mul(vk.beta[i+privateLen], public_m[i]))
		}
	}
	t1 := BLS381.NewECP2()
	t1.Copy(showMats.kappa)
	t1.Add(aggr)

	t2 := BLS381.NewECP()
	t2.Copy(sig.sig2)
	t2.Add(showMats.nu)

	Gt1 := params.G.Pair(sig.sig1, t1)
	Gt2 := params.G.Pair(t2, vk.g2)

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

func AggregateVerificationKeys(params *Params, vks []*VerificationKey, pp *PolynomialPoints) *VerificationKey {
	var l []*BLS381.BIG
	var alpha *BLS381.ECP2
	beta := make([]*BLS381.ECP2, len(vks[0].beta))

	if pp != nil {
		t := len(vks)
		l = make([]*BLS381.BIG, t)
		// for i := 1; i < t+1; i++ {
		// 	l[i-1] = utils.LagrangeBasis(t, params.G.Ord, i, 0)
		// }
		for i := 0; i < t; i++ {
			l[i] = utils.LagrangeBasis(i, params.G.Ord, pp.xs, 0)
		}

		alpha = BLS381.G2mul(vks[0].alpha, l[0])
		for i := 1; i < len(vks); i++ {
			alpha.Add(BLS381.G2mul(vks[i].alpha, l[i]))
		}

		for i := 0; i < len(vks[0].beta); i++ {
			beta[i] = BLS381.G2mul(vks[0].beta[i], l[0])
		}

		for i := 1; i < len(vks); i++ { // we already got values from first set of keys
			for j := 0; j < len(beta); j++ {
				beta[j].Add(BLS381.G2mul(vks[i].beta[j], l[i]))
			}
		}

	} else {
		alpha = BLS381.NewECP2()
		alpha.Copy(vks[0].alpha)
		for i := 1; i < len(vks); i++ {
			alpha.Add(vks[i].alpha)
		}

		for i := 0; i < len(vks[0].beta); i++ {
			beta[i] = BLS381.NewECP2()
			beta[i].Copy(vks[0].beta[i])
		}

		for i := 1; i < len(vks); i++ { // we already copied values from first set of keys
			for j := 0; j < len(beta); j++ {
				beta[j].Add(vks[i].beta[j])
			}
		}
	}

	return &VerificationKey{
		g2:    vks[0].g2,
		alpha: alpha,
		beta:  beta,
	}
}

func AggregateSignatures(params *Params, sigs []*Signature, pp *PolynomialPoints) *Signature {
	// in principle there's no need to copy sig1 as it's the same among all signatures and we can reuse one of the pointers
	var l []*BLS381.BIG
	var sig2 *BLS381.ECP
	if pp != nil {
		t := len(sigs)
		l = make([]*BLS381.BIG, t)
		// for i := 1; i < t+1; i++ {
		// 	l[i-1] = utils.LagrangeBasis(t, params.G.Ord, i, 0)
		// }
		for i := 0; i < t; i++ {
			l[i] = utils.LagrangeBasis(i, params.G.Ord, pp.xs, 0)
		}
		sig2 = BLS381.G1mul(sigs[0].sig2, l[0])
		for i := 1; i < len(sigs); i++ {
			sig2.Add(BLS381.G1mul(sigs[i].sig2, l[i]))
		}
	} else {
		sig2 = BLS381.NewECP()
		sig2.Copy(sigs[0].sig2)

		for i := 1; i < len(sigs); i++ {
			sig2.Add(sigs[i].sig2)
		}
	}

	return &Signature{
		sig1: sigs[0].sig1,
		sig2: sig2,
	}
}
