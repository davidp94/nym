// todo: tests for all other methods
package commands_test

import (
	"testing"

	"github.com/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/crypto/elgamal"
	"github.com/jstuczyn/CoconutGo/server/commands"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func TestBlindSignMarshal(t *testing.T) {
	params, _ := coconut.Setup(constants.SetupAttrs)
	G := params.G
	pubM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}
	privM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}
	_, gamma := elgamal.Keygen(G)
	blindSignMats, _ := coconut.PrepareBlindSign(params, gamma, pubM, privM)

	cmd := commands.NewBlindSign(blindSignMats, gamma, pubM)
	data, err := cmd.MarshalBinary()
	assert.Nil(t, err)

	blindSign := commands.BlindSign{}
	assert.Nil(t, blindSign.UnmarshalBinary(data))
	// todo: deep compare of all elems of bs

}
