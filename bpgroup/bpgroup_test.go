package bpgroup_test

import (
	"testing"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// Check if the bilinearity property holds, i.e. e(aP, bQ) = e(P, Q)^ab
func TestPairing(t *testing.T) {
	G := bpgroup.New()

	P := BLS381.G1mul(G.Gen1, G.Ord)
	if !P.Is_infinity() {
		t.Error("rP != 0")
	}

	Q := BLS381.G2mul(G.Gen2, G.Ord)
	if !Q.Is_infinity() {
		t.Error("rQ != 0")
	}

	// generate random g1 and g2 elements
	x := BLS381.Randomnum(G.Ord, G.Rng)
	y := BLS381.Randomnum(G.Ord, G.Rng)

	P = BLS381.G1mul(G.Gen1, x)
	Q = BLS381.G2mul(G.Gen2, y)

	W := G.Pair(P, Q)

	g := BLS381.GTpow(W, G.Ord)
	if !g.Isunity() {
		t.Error("g^r != 1")
	}

	a := BLS381.Randomnum(G.Ord, G.Rng)
	p := BLS381.G1mul(P, a)
	gt1 := G.Pair(p, Q)
	gt2 := BLS381.GTpow(G.Pair(P, Q), a)
	if !gt1.Equals(gt2) {
		t.Error("e(aP, Q) != e(P, Q)^a")
	}

	a = BLS381.Randomnum(G.Ord, G.Rng)
	q := BLS381.G2mul(Q, a)
	gt1 = G.Pair(P, q)
	gt2 = BLS381.GTpow(G.Pair(P, Q), a)
	if !gt1.Equals(gt2) {
		t.Error("e(P, aQ) != e(P, Q)^a")
	}

	a = BLS381.Randomnum(G.Ord, G.Rng)
	p = BLS381.G1mul(P, a)
	q = BLS381.G2mul(Q, a)
	gt1 = G.Pair(P, q)
	gt2 = G.Pair(p, Q)
	if !gt1.Equals(gt2) {
		t.Error("e(aP, Q) != e(P, aQ)")
	}

	a = BLS381.Randomnum(G.Ord, G.Rng)
	b := BLS381.Randomnum(G.Ord, G.Rng)
	p = BLS381.G1mul(P, a)
	q = BLS381.G2mul(Q, b)
	c := BLS381.Modmul(a, b, G.Ord)
	gt1 = G.Pair(p, q)
	gt2 = BLS381.GTpow(G.Pair(P, Q), c)
	if !gt1.Equals(gt2) {
		t.Error("e(aP, bQ) != e(P, Q)^ab")
	}

}
