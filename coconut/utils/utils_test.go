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
}
