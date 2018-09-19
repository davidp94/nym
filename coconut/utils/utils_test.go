package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

func TestPolyEval(t *testing.T) {
	order := BLS381.NewBIGints(BLS381.CURVE_Order)
	tests := []struct {
		coeff    []*BLS381.BIG
		x        int
		o        *BLS381.BIG
		expected *BLS381.BIG
	}{
		{coeff: []*BLS381.BIG{BLS381.NewBIGint(20), BLS381.NewBIGint(21), BLS381.NewBIGint(42)},
			x:        0,
			o:        order,
			expected: BLS381.NewBIGint(20),
		},
		{coeff: []*BLS381.BIG{BLS381.NewBIGint(0), BLS381.NewBIGint(0), BLS381.NewBIGint(0)},
			x:        4,
			o:        order,
			expected: BLS381.NewBIGint(0),
		},
		{coeff: []*BLS381.BIG{BLS381.NewBIGint(1), BLS381.NewBIGint(2), BLS381.NewBIGint(3), BLS381.NewBIGint(4), BLS381.NewBIGint(5)},
			x:        10,
			o:        order,
			expected: BLS381.NewBIGint(54321),
		},
	}

	for _, test := range tests {
		comp := BLS381.Comp(test.expected, utils.PolyEval(test.coeff, test.x, test.o))
		assert.Zero(t, comp)
	}
}

func TestLagrangeBasis(t *testing.T) {
	// polynomial of order k - 1
	G := bpgroup.New()
	ks := []int{1, 3, 5, 10}
	for _, k := range ks {
		v := make([]*BLS381.BIG, k)
		ls := make([]*BLS381.BIG, k)
		vals := make([]*BLS381.BIG, k)
		for i := range v {
			v[i] = BLS381.Randomnum(G.Ord, G.Rng)
		}
		for i := range v {
			ls[i] = utils.LagrangeBasis(k, G.Ord, i+1, 0)
			vals[i] = utils.PolyEval(v, i+1, G.Ord)
		}
		interpolated := BLS381.Modmul(ls[0], vals[0], G.Ord)
		for i := 1; i < len(v); i++ {
			interpolated = interpolated.Plus(BLS381.Modmul(ls[i], vals[i], G.Ord))
		}
		interpolated.Mod(G.Ord)
		assert.Zero(t, BLS381.Comp(v[0], interpolated))

	}

	// k := 3

	// l1 := utils.LagrangeBasis(k, G.Ord, 1, 0)
	// l2 := utils.LagrangeBasis(k, G.Ord, 2, 0)
	// l3 := utils.LagrangeBasis(k, G.Ord, 3, 0)
	// val1 := utils.PolyEval(v, 1, G.Ord)
	// val2 := utils.PolyEval(v, 2, G.Ord)
	// val3 := utils.PolyEval(v, 3, G.Ord)

	// interpolated := BLS381.Modmul(l1, val1, G.Ord).Plus(BLS381.Modmul(l2, val2, G.Ord)).Plus(BLS381.Modmul(l3, val3, G.Ord))
	// interpolated.Mod(G.Ord)
	// comp := BLS381.Comp(v[0], interpolated)
	// assert.Zero(t, comp)

	// return
	// G := bpgroup.New()

	// k := 3
	// v := make([]*BLS381.BIG, k)
	// v[0] = BLS381.NewBIGint(1234)
	// v[1] = BLS381.NewBIGint(166)
	// v[2] = BLS381.NewBIGint(94)

	// val1 := utils.PolyEval(v, 1, G.Ord)
	// val2 := utils.PolyEval(v, 2, G.Ord)
	// val3 := utils.PolyEval(v, 3, G.Ord)
	// assert.Zero(t, BLS381.Comp(val1, BLS381.NewBIGint(1494)))
	// assert.Zero(t, BLS381.Comp(val2, BLS381.NewBIGint(1942)))
	// assert.Zero(t, BLS381.Comp(val3, BLS381.NewBIGint(2578)))

	// l1 := utils.LagrangeBasis(k, G.Ord, 1, 0)
	// l2 := utils.LagrangeBasis(k, G.Ord, 2, 0)
	// l3 := utils.LagrangeBasis(k, G.Ord, 3, 0)
	// t.Error("l1: ", l1.ToString())
	// t.Error("l2: ", l2.ToString())

	// t1 := BLS381.Modmul(l1, val1, G.Ord)
	// t2 := BLS381.Modmul(l2, val2, G.Ord)
	// t3 := BLS381.Modmul(l3, val3, G.Ord)

	// t.Error("target: ", v[0].ToString())
	// t.Error("t1: ", t1.ToString())
	// t.Error("t2: ", t2.ToString())
	// t.Error("t3: ", t3.ToString())

	// interpolated := t1.Plus(t2)
	// interpolated = interpolated.Plus(t3)
	// interpolated.Mod(G.Ord)

	// // interpolated = BLS381.Modneg(interpolated, G.Ord)

	// t.Error("inter:", interpolated.ToString())
	// comp := BLS381.Comp(v[0], interpolated)
	// assert.Zero(t, comp)
}
