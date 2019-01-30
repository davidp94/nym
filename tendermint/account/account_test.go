// account_test.go - tests for the account package
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
package account_test

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/common/utils"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func TestKeygen(t *testing.T) {
	S, W := account.Keygen()
	s := Curve.FromBytes(S)
	w := Curve.ECP_fromBytes(W)
	G := Curve.ECP_generator()
	assert.True(t, w.Equals(Curve.G1mul(G, s)))
}

func TestSignAndValidate(t *testing.T) {
	S, W := account.Keygen()

	msg, err := utils.GenerateRandomBytes(128)
	assert.Nil(t, err)

	sig := S.SignBytes(msg)

	assert.True(t, W.VerifyBytes(msg, sig))

	// Mutate single bit of the signature
	sig[42] ^= byte(0x01)

	assert.False(t, W.VerifyBytes(msg, sig))
}

func TestCompressPublicKey(t *testing.T) {
	S, W := account.Keygen()
	lenBefore := len(W)
	err := W.Compress()
	assert.Nil(t, err)
	lenAfter := len(W)
	assert.True(t, lenAfter < lenBefore)

	msg, err := utils.GenerateRandomBytes(128)
	assert.Nil(t, err)

	sig := S.SignBytes(msg)

	assert.True(t, W.VerifyBytes(msg, sig))

	// Mutate single bit of the signature
	sig[42] ^= byte(0x01)

	assert.False(t, W.VerifyBytes(msg, sig))
}
