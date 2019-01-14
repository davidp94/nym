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

	"0xacab.org/jstuczyn/CoconutGo/common/comm/packet"

	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func getRandomAttributes(G *bpgroup.BpGroup, n int) []*Curve.BIG {
	attrs := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		attrs[i] = Curve.Randomnum(G.Order(), G.Rng())
	}
	return attrs
}

func TestCommandToMarshaledPacket(t *testing.T) {
	validCmd, _ := commands.NewVerificationKeyRequest()

	b, err := commands.CommandToMarshaledPacket(validCmd)
	assert.NotNil(t, b)
	assert.Nil(t, err)

	// a command is basically a protobuf message and ProtoLambda implements correct interface
	invalidCmd := &coconut.ProtoLambda{}
	b, err = commands.CommandToMarshaledPacket(invalidCmd)
	assert.Nil(t, b)
	assert.Error(t, err)
}

func TestFromBytes(t *testing.T) {
	validCmd, _ := commands.NewVerificationKeyRequest()

	b, err := commands.CommandToMarshaledPacket(validCmd)
	assert.NotNil(t, b)
	assert.Nil(t, err)

	packet, err := packet.FromBytes(b)
	assert.Nil(t, err)

	cmd, err := commands.FromBytes(b)
	assert.Nil(t, cmd)
	assert.Error(t, err)

	cmd, err = commands.FromBytes(packet.Payload())
	assert.NotNil(t, cmd)
	assert.Nil(t, err)
}

func TestNewSignRequest(t *testing.T) {
	G := bpgroup.New()

	validPubMs := [][]*Curve.BIG{
		getRandomAttributes(G, 1),
		getRandomAttributes(G, 3),
		getRandomAttributes(G, 5),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		{},
		append(validPubMs[2], nil),
	}

	for _, validPubM := range validPubMs {
		sr, err := commands.NewSignRequest(validPubM)
		assert.NotNil(t, sr)
		assert.Nil(t, err)
	}

	for _, invalidPubM := range invalidPubMs {
		sr, err := commands.NewSignRequest(invalidPubM)
		assert.Nil(t, sr)
		assert.Error(t, err)
	}

}

func TestNewVerifyRequqest(t *testing.T) {
	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		{},
		append(validPubMs[2], nil),
	}

	sk, _, err := coconut.Keygen(params)
	assert.Nil(t, err)

	// a single one is enough as this function does not check validity of signature, simply whether it is there
	validSig, err := coconut.Sign(params, sk, validPubMs[2])
	assert.Nil(t, err)

	invalidSigs := []*coconut.Signature{
		nil,
		{},
		coconut.NewSignature(validSig.Sig1(), nil),
		coconut.NewSignature(nil, validSig.Sig2()),
	}

	for _, validPubM := range validPubMs {
		sr, err := commands.NewVerifyRequest(validPubM, validSig)
		assert.NotNil(t, sr)
		assert.Nil(t, err)

		for _, invalidSig := range invalidSigs {
			sr, err = commands.NewVerifyRequest(validPubM, invalidSig)
			assert.Nil(t, sr)
			assert.Error(t, err)
		}
	}

	for _, invalidPubM := range invalidPubMs {
		sr, err := commands.NewVerifyRequest(invalidPubM, validSig)
		assert.Nil(t, sr)
		assert.Error(t, err)

		for _, invalidSig := range invalidSigs {
			sr, err = commands.NewVerifyRequest(invalidPubM, invalidSig)
			assert.Nil(t, sr)
			assert.Error(t, err)
		}
	}

}

func TestNewBlindSignRequest(t *testing.T) {
	params, err := coconut.Setup(10)
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		{},
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		append(validPubMs[3], nil),
	}

	validPrivMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	_, validEgPub := elgamal.Keygen(params.G)
	invalidEgPub := elgamal.NewPublicKey(validEgPub.P(), validEgPub.G(), nil)

	for _, validPubM := range validPubMs {
		for _, validPrivM := range validPrivMs {
			lambda, err := coconut.PrepareBlindSign(params, validEgPub, validPubM, validPrivM)
			assert.Nil(t, err)

			bse, err := commands.NewBlindSignRequest(lambda, validEgPub, validPubM)
			assert.NotNil(t, bse)
			assert.Nil(t, err)

			bse, err = commands.NewBlindSignRequest(lambda, invalidEgPub, validPubM)
			assert.Nil(t, bse)
			assert.Error(t, err)
		}
	}

	for _, invalidPubM := range invalidPubMs {
		for _, validPrivM := range validPrivMs {
			lambda, _ := coconut.PrepareBlindSign(params, validEgPub, invalidPubM, validPrivM)

			bse, err := commands.NewBlindSignRequest(lambda, validEgPub, invalidPubM)
			assert.Nil(t, bse)
			assert.Error(t, err)

			bse, err = commands.NewBlindSignRequest(lambda, invalidEgPub, invalidPubM)
			assert.Nil(t, bse)
			assert.Error(t, err)
		}
	}
}

func TestNewBlindVerifyRequest(t *testing.T) {
	params, err := coconut.Setup(10)
	assert.Nil(t, err)

	sk, vk, err := coconut.Keygen(params)
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		{},
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		append(validPubMs[3], nil),
	}

	validPrivMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	// similarly to before, validity is not checked so any correctly constructed signature can be used for the test
	validSig, err := coconut.Sign(params, sk, validPubMs[2])
	assert.Nil(t, err)

	invalidSigs := []*coconut.Signature{
		nil,
		{},
		coconut.NewSignature(validSig.Sig1(), nil),
		coconut.NewSignature(nil, validSig.Sig2()),
	}

	for _, validPubM := range validPubMs {
		for _, validPrivM := range validPrivMs {
			theta, err := coconut.ShowBlindSignature(params, vk, validSig, validPrivM)
			assert.Nil(t, err)

			bsr, err := commands.NewBlindVerifyRequest(theta, validSig, validPubM)
			assert.NotNil(t, bsr)
			assert.Nil(t, err)

			for _, invalidSig := range invalidSigs {
				bsr, err := commands.NewBlindVerifyRequest(theta, invalidSig, validPubM)
				assert.Nil(t, bsr)
				assert.Error(t, err)
			}
		}
	}

	for _, invalidPubM := range invalidPubMs {
		for _, validPrivM := range validPrivMs {
			theta, err := coconut.ShowBlindSignature(params, vk, validSig, validPrivM)
			assert.Nil(t, err)

			bsr, err := commands.NewBlindVerifyRequest(theta, validSig, invalidPubM)
			assert.Nil(t, bsr)
			assert.Error(t, err)

			for _, invalidSig := range invalidSigs {
				bsr, err := commands.NewBlindVerifyRequest(theta, invalidSig, invalidPubM)
				assert.Nil(t, bsr)
				assert.Error(t, err)
			}
		}
	}
}
