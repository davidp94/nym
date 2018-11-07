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

func TestBlindVerifyMarshal(t *testing.T) {
	params, _ := coconut.Setup(constants.SetupAttrs)
	G := params.G
	pubM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}
	privM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}

	sk, vk, _ := coconut.Keygen(params)
	d, gamma := elgamal.Keygen(params.G)
	blindSignMats, _ := coconut.PrepareBlindSign(params, gamma, pubM, privM)
	blindedSignature, _ := coconut.BlindSign(params, sk, blindSignMats, gamma, pubM)
	sig := coconut.Unblind(params, blindedSignature, d)
	blindShowMats, _ := coconut.ShowBlindSignature(params, vk, sig, privM)

	cmd := commands.NewBlindVerify(blindShowMats, sig, pubM)
	data, err := cmd.MarshalBinary()
	assert.Nil(t, err)

	blindVerify := commands.BlindVerify{}
	assert.Nil(t, blindVerify.UnmarshalBinary(data))

	for i := range cmd.PubM() {
		assert.Zero(t, Curve.Comp(cmd.PubM()[i], blindVerify.PubM()[i]))
	}

	assert.True(t, cmd.Sig().Sig1().Equals(blindVerify.Sig().Sig1()))
	assert.True(t, cmd.Sig().Sig2().Equals(blindVerify.Sig().Sig2()))

	assert.True(t, cmd.BlindShowMats().Kappa().Equals(blindVerify.BlindShowMats().Kappa()))
	assert.True(t, cmd.BlindShowMats().Nu().Equals(blindVerify.BlindShowMats().Nu()))

	assert.Zero(t, Curve.Comp(cmd.BlindShowMats().Proof().C(), blindVerify.BlindShowMats().Proof().C()))
	assert.Zero(t, Curve.Comp(cmd.BlindShowMats().Proof().Rt(), blindVerify.BlindShowMats().Proof().Rt()))
	for i := range cmd.BlindShowMats().Proof().Rm() {
		assert.Zero(t, Curve.Comp(cmd.BlindShowMats().Proof().Rm()[i], blindVerify.BlindShowMats().Proof().Rm()[i]))
	}

	assert.True(t, coconut.BlindVerify(params, vk, cmd.Sig(), cmd.BlindShowMats(), cmd.PubM()))
	assert.True(t, coconut.BlindVerify(params, vk, blindVerify.Sig(), blindVerify.BlindShowMats(), blindVerify.PubM()))

}
