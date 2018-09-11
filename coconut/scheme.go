// currently this version does not include threshold credentials or blind signatures
// those will be added in further iteration

package coconut

import (
	"fmt"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
	// "github.com/milagro-crypto/amcl/version3/go/amcl/BN254"
)

type Signature struct {
	sig1 *BLS381.ECP
	sig2 *BLS381.ECP
}

// q is the number of attributes embedded in the credential
func Setup(q int) (*bpgroup.BpGroup, []*BLS381.ECP) {
	hs := []*BLS381.ECP{}
	for i := 0; i < q; i++ {
		hn, err := hashStringToG1(amcl.SHA256, fmt.Sprintf("h%d", i))
		if err != nil {
			panic(err)
		}
		hs = append(hs, hn)
	}
	G := bpgroup.New()
	return G, hs
}

// todo: to be replaced by generation of keys threshold signature (by a TTP)
// right now it is keygen as if performed by a single isolated entity
func Keygen(G *bpgroup.BpGroup, hs []*BLS381.ECP) ([]*BLS381.BIG, []*BLS381.ECP2) {
	q := len(hs)

	sk := []*BLS381.BIG{}
	vk := []*BLS381.ECP2{G.Gen2}

	// todo: benchmark the keygen on high number of attributes and see if it is worth to parallelize it with goroutines
	// while it might not be hugely beneficial right now, it may be useful for threshold signatures
	for i := 0; i < q+1; i++ {
		x := BLS381.Randomnum(G.Ord, G.Rng)
		y := BLS381.G2mul(G.Gen2, x)
		sk = append(sk, x)
		vk = append(vk, y)
	}

	return sk, vk
}

// this is a very temporary solution that will be modified once private attributes are introduced
// the sole point of it is to have some deterministic attribute dependant h value
func getBaseFromAttributes(public_m []*BLS381.BIG) *BLS381.ECP {
	s := ""
	for i := 0; i < len(public_m); i++ {
		pubBytes := make([]byte, 48)
		public_m[i].ToBytes(pubBytes)
		s += string(pubBytes)
	}
	h, err := hashStringToG1(amcl.SHA256, s)
	if err != nil {
		panic(err)
	}
	return h
}

// at this iteration, only public attributes are considered
func Sign(G *bpgroup.BpGroup, sk []*BLS381.BIG, public_m []*BLS381.BIG) Signature {
	// todo: also consider parallelization
	// todo later on: decide on concrete generation of h
	// todo: deal with case when len(sk) != len(public_m) + 1 - throw some error

	h := getBaseFromAttributes(public_m)
	// for some reason in js version i used DBIG? check why
	// also took copy and then mod of all BIGs
	K := BLS381.NewBIGcopy(sk[0]) // K = x0
	for i := 0; i < len(public_m); i++ {
		tmp := BLS381.Modmul(sk[i+1], public_m[i], G.Ord) // (xi * ai)
		K = K.Plus(tmp)                                   // K = x0 + (x1 * a1) + ...
	}
	sig := BLS381.G1mul(h, K) // sig = h^(x0 + (x1 * a1) + ... )

	return Signature{h, sig}
}

// similarly to Sign, this iteration only considers public attributes
func Verify(G *bpgroup.BpGroup, vk []*BLS381.ECP2, public_m []*BLS381.BIG, sig Signature) bool {
	// todo: same concerns as with Sign
	// h := getBaseFromAttributes(public_m)

	// ensure G.Gen2 == vk[0] ?
	K := BLS381.NewECP2()
	K.Copy(vk[1]) // K = X0
	for i := 0; i < len(public_m); i++ {
		tmp := BLS381.G2mul(vk[i+2], public_m[i]) // (Yi * ai)
		K.Add(tmp)                                // K = X0 + (Y1 * a1) + ...
	}
	// need to affine K?

	// todo: evaluate both pairings in parallel using goroutines
	Gt1 := G.Pair(sig.sig1, K)
	Gt2 := G.Pair(sig.sig2, vk[0])
	return !sig.sig1.Is_infinity() && Gt1.Equals(Gt2)
}

func Randomize(G *bpgroup.BpGroup, sig Signature) Signature {
	t := BLS381.Randomnum(G.Ord, G.Rng)
	return Signature{BLS381.G1mul(sig.sig1, t), BLS381.G1mul(sig.sig2, t)}
}

// todo: special case for threshold
func AggregateVerificationKeys(G *bpgroup.BpGroup, vks [][]*BLS381.ECP2) []*BLS381.ECP2 {
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
func AggregateSignatures(G *bpgroup.BpGroup, sigs []Signature) Signature {
	// in principle there's no need to copy sig1 as it's the same among all signatures and we can reuse one of the pointers
	sig2Cp := BLS381.NewECP()
	sig2Cp.Copy(sigs[0].sig2)

	for i := 1; i < len(sigs); i++ {
		sig2Cp.Add(sigs[i].sig2)
	}

	return Signature{
		sig1: sigs[0].sig1,
		sig2: sig2Cp,
	}
}
