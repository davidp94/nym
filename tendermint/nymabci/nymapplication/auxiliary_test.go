// auxiliary_test.go - tests of auxiliary functions of the nymapplication
// Copyright (C) 2019  Jedrzej Stuczynski.
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

package nymapplication

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func TestPrefixKey(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte{},
		[]byte{0x00},
		[]byte("lorem lipsum"),
	}

	for _, t1 := range tests {
		for _, t2 := range tests {
			res := prefixKey(t1, t2)
			assert.Len(t, res, len(t1)+len(t2))
			assert.Zero(t, bytes.Compare(res[:len(t1)], t1))
			assert.Zero(t, bytes.Compare(res[len(t1):], t2))
		}
	}
}

func TestRandomInt(t *testing.T) {
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))

	// ensure it won't get stuck in infinite loop when there are no valid choices
	r := randomInt(map[int]struct{}{1: struct{}{}}, 2, randSource)
	assert.Equal(t, r, -1)

	r = randomInt(map[int]struct{}{}, 1, randSource)
	assert.Equal(t, r, -1)

	r = randomInt(map[int]struct{}{1: struct{}{}}, 3, randSource)
	assert.Equal(t, r, 2)

	r = randomInt(map[int]struct{}{}, 10, randSource)
	assert.True(t, r > 0 && r < 10)
}

func TestRandomInts(t *testing.T) {
	source := rand.NewSource(time.Now().UnixNano())

	rs, err := randomInts(-1, 10, source)
	assert.Nil(t, rs)
	assert.Error(t, err)

	rs, err = randomInts(1, 1, source)
	assert.Nil(t, rs)
	assert.Error(t, err)

	rs, err = randomInts(4, 10, nil)
	assert.Nil(t, rs)
	assert.Error(t, err)

	rs, err = randomInts(4, 10, source)
	assert.Len(t, rs, 4)
	assert.Nil(t, err)
}

func TestCheckIfAccountExists(t *testing.T) {
	bpgroup := bpgroup.New() // for easy access to rng
	x := Curve.Randomnum(bpgroup.Order(), bpgroup.Rng())
	g := Curve.G1mul(bpgroup.Gen1(), x)

	uncompressed := make([]byte, constants.ECPLenUC)
	compressed := make([]byte, constants.ECPLen)

	g.ToBytes(uncompressed, false)
	g.ToBytes(compressed, true)

	malformedCompressed := make([]byte, len(compressed))
	copy(malformedCompressed, compressed)
	malformedCompressed[0] = 0x01

	invalidAddresses := [][]byte{
		nil,
		[]byte{},
		[]byte("foo"),
		malformedCompressed,
	}

	// before address is added, all need to fail
	for _, addr := range append(invalidAddresses, compressed, uncompressed) {
		assert.False(t, app.checkIfAccountExists(addr))
	}

	// will be tested below, for now we use address we know is 100% valid
	app.createNewAccountOp(compressed)

	for _, addr := range append(invalidAddresses, uncompressed) {
		assert.False(t, app.checkIfAccountExists(addr))
	}

	assert.True(t, app.checkIfAccountExists(compressed))
}

func TestCreateNewAccountOp(t *testing.T) {
	bpgroup := bpgroup.New() // for easy access to rng
	x := Curve.Randomnum(bpgroup.Order(), bpgroup.Rng())
	g := Curve.G1mul(bpgroup.Gen1(), x)

	var uncompressed account.ECPublicKey = make([]byte, constants.ECPLenUC)
	var compressed account.ECPublicKey = make([]byte, constants.ECPLen)

	g.ToBytes(uncompressed, false)
	g.ToBytes(compressed, true)

	malformedCompressed := make([]byte, len(compressed))
	copy(malformedCompressed, compressed)
	malformedCompressed[0] = 0x01

	invalidAddresses := [][]byte{
		nil,
		[]byte{},
		[]byte("foo"),
		malformedCompressed,
	}

	// while this might not be a 100% valid point on the curve, it's sufficient for that test as we don't want
	// overlapping compressed results
	compressed[8] ^= 1

	for _, addr := range invalidAddresses {
		assert.False(t, app.createNewAccountOp(addr))
		assert.False(t, app.checkIfAccountExists(addr)) // make sure it didn't fail silently
	}

	assert.True(t, app.createNewAccountOp(uncompressed))
	uncompressed.Compress()
	assert.True(t, app.checkIfAccountExists(uncompressed))

	assert.True(t, app.createNewAccountOp(compressed))
	assert.True(t, app.checkIfAccountExists(compressed))
}

func TestTransferFundsOp(t *testing.T) {
	// create a 'debug' account with bunch of funds
	bpgroup := bpgroup.New() // for easy access to rng
	x := Curve.Randomnum(bpgroup.Order(), bpgroup.Rng())
	g_1 := Curve.G1mul(bpgroup.Gen1(), x)
	acc1 := make([]byte, constants.ECPLen)
	g_1.ToBytes(acc1, true)

	// need to 'workaround' to set initial balance
	balance := make([]byte, 8)
	binary.BigEndian.PutUint64(balance, 1000)
	app.state.db.Set(prefixKey(accountsPrefix, acc1), balance)

	// create some destination account
	y := Curve.Randomnum(bpgroup.Order(), bpgroup.Rng())
	g_2 := Curve.G1mul(bpgroup.Gen1(), y)
	acc2 := make([]byte, constants.ECPLen)
	g_2.ToBytes(acc2, true)
	app.createNewAccountOp(acc2)

	// create another valid address but don't include it in the db
	z := Curve.Randomnum(bpgroup.Order(), bpgroup.Rng())
	g_3 := Curve.G1mul(bpgroup.Gen1(), z)
	acc3 := make([]byte, constants.ECPLen)
	g_3.ToBytes(acc3, true)
	// is not included in the db

	// first test invalid addresses; validateTransfer should theoretically catch all of those
	invalidAddresses := [][]byte{
		nil,
		[]byte{},
		[]byte("foo"),
		acc3,
	}

	for _, invalidAddr := range invalidAddresses {
		retCode, _ := app.transferFundsOp(invalidAddr, acc1, 42)
		assert.NotEqual(t, code.OK, retCode)
	}

	for _, invalidAddr := range invalidAddresses {
		retCode, _ := app.transferFundsOp(acc1, invalidAddr, 42)
		assert.NotEqual(t, code.OK, retCode)
	}

	// empty source
	retCode, _ := app.transferFundsOp(acc2, acc1, 42)
	assert.NotEqual(t, code.OK, retCode)
	// not enough funds on source
	retCode, _ = app.transferFundsOp(acc1, acc2, 100000000)
	assert.NotEqual(t, code.OK, retCode)

	// dest doesnt exist
	retCode, _ = app.transferFundsOp(acc1, acc3, 42)
	assert.NotEqual(t, code.OK, retCode)
	assert.False(t, app.checkIfAccountExists(acc3)) // make sure it wasn't created...

	// a valid transfer
	retCode, _ = app.transferFundsOp(acc1, acc2, 42)
	assert.Equal(t, code.OK, retCode)

	acc1B, _ := app.queryBalance(acc1)
	acc2B, _ := app.queryBalance(acc2)

	acc1Balance := binary.BigEndian.Uint64(acc1B)
	acc2Balance := binary.BigEndian.Uint64(acc2B)
	assert.Equal(t, uint64(1000-42), acc1Balance)
	assert.Equal(t, uint64(42), acc2Balance)
}
