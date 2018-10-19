package coconutclientworker_test

import (
	"testing"

	"github.com/eapache/channels"
	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/coconutclientworker"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobworker"

	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

func TestDoG1Mul(t *testing.T) {
	G := bpgroup.New()
	g1 := G.Gen1()
	x := Curve.Randomnum(G.Order(), G.Rng())
	y := Curve.Randomnum(G.Order(), G.Rng())

	infch := channels.NewInfiniteChannel()
	ccw := coconutclientworker.New(infch)
	jobworker.New(infch.Out(), 1)
	jobworker.New(infch.Out(), 2)

	ccw.DoG1Mul(g1, x, y)

}
