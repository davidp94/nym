// todo: tests for all other methods

// commands_test.go - tests for commands for coconut server
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

package commands_test

import (
	"testing"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/crypto/elgamal"
	"github.com/jstuczyn/CoconutGo/server/commands"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func TestBlindSignMarshal(t *testing.T) {
	params, _ := coconut.Setup(5)
	G := params.G
	pubM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}
	privM := []*Curve.BIG{
		Curve.Randomnum(G.Order(), G.Rng()),
		Curve.Randomnum(G.Order(), G.Rng()),
		Curve.Randomnum(G.Order(), G.Rng()),
	}
	_, egPub := elgamal.Keygen(G)
	blindSignMats, _ := coconut.PrepareBlindSign(params, egPub, pubM, privM)

	cmd := commands.NewBlindSign(blindSignMats, egPub, pubM)
	data, err := cmd.MarshalBinary()
	assert.Nil(t, err)

	blindSign := commands.BlindSign{}
	assert.Nil(t, blindSign.UnmarshalBinary(data))

	for i := range cmd.PubM() {
		assert.Zero(t, Curve.Comp(cmd.PubM()[i], blindSign.PubM()[i]))
	}

	assert.True(t, cmd.EgPub().G.Equals(blindSign.EgPub().G))
	assert.Zero(t, Curve.Comp(cmd.EgPub().P, blindSign.EgPub().P))
	assert.True(t, cmd.EgPub().Gamma.Equals(blindSign.EgPub().Gamma))

	assert.True(t, cmd.BlindSignMats().Cm().Equals(blindSign.BlindSignMats().Cm()))
	for i := range cmd.BlindSignMats().Enc() {
		assert.True(t, cmd.BlindSignMats().Enc()[i].C1().Equals(blindSign.BlindSignMats().Enc()[i].C1()))
		assert.True(t, cmd.BlindSignMats().Enc()[i].C2().Equals(blindSign.BlindSignMats().Enc()[i].C2()))
	}

	assert.Zero(t, Curve.Comp(cmd.BlindSignMats().Proof().C(), blindSign.BlindSignMats().Proof().C()))
	assert.Zero(t, Curve.Comp(cmd.BlindSignMats().Proof().Rr(), blindSign.BlindSignMats().Proof().Rr()))
	for i := range cmd.BlindSignMats().Proof().Rk() {
		assert.Zero(t, Curve.Comp(cmd.BlindSignMats().Proof().Rk()[i], blindSign.BlindSignMats().Proof().Rk()[i]))
	}

	for i := range cmd.BlindSignMats().Proof().Rm() {
		assert.Zero(t, Curve.Comp(cmd.BlindSignMats().Proof().Rm()[i], blindSign.BlindSignMats().Proof().Rm()[i]))
	}

	// sanity check
	assert.True(t, coconut.VerifySignerProof(params, egPub.Gamma, blindSignMats))
	assert.True(t, coconut.VerifySignerProof(params, egPub.Gamma, blindSign.BlindSignMats()))

}

// nolint: lll
func TestBlindVerifyMarshal(t *testing.T) {
	params, _ := coconut.Setup(5)
	G := params.G
	pubM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}
	privM := []*Curve.BIG{
		Curve.Randomnum(G.Order(), G.Rng()),
		Curve.Randomnum(G.Order(), G.Rng()),
		Curve.Randomnum(G.Order(), G.Rng()),
	}

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

	assert.True(t, bool(coconut.BlindVerify(params, vk, cmd.Sig(), cmd.BlindShowMats(), cmd.PubM())))
	assert.True(t, bool(coconut.BlindVerify(params, vk, blindVerify.Sig(), blindVerify.BlindShowMats(), blindVerify.PubM())))

}
