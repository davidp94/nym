// check_test.go - tests of check functions of the nymapplication
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
	"encoding/binary"
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	proto "github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func TestValidateTransfer(t *testing.T) {
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
		retCode, _ := app.validateTransfer(invalidAddr, acc1, 42)
		assert.NotEqual(t, code.OK, retCode)
	}

	for _, invalidAddr := range invalidAddresses {
		retCode, _ := app.validateTransfer(acc1, invalidAddr, 42)
		assert.NotEqual(t, code.OK, retCode)
	}

	// self transfer between invalid
	retCode, _ := app.validateTransfer(acc3, acc3, 42)
	assert.NotEqual(t, code.OK, retCode)

	// self transfer between valid
	retCode, _ = app.validateTransfer(acc1, acc1, 42)
	assert.NotEqual(t, code.OK, retCode)

	// empty source
	retCode, _ = app.validateTransfer(acc2, acc1, 42)
	assert.NotEqual(t, code.OK, retCode)
	// not enough funds on source
	retCode, _ = app.validateTransfer(acc1, acc2, 100000000)
	assert.NotEqual(t, code.OK, retCode)

	// dest doesnt exist
	retCode, _ = app.validateTransfer(acc1, acc3, 42)
	assert.NotEqual(t, code.OK, retCode)

	// a valid transfer
	retCode, _ = app.validateTransfer(acc1, acc2, 42)
	assert.Equal(t, code.OK, retCode)
}

func TestCheckNewAccountTx(t *testing.T) {
	emptyReq, err := proto.Marshal(&transaction.NewAccountRequest{})
	assert.Nil(t, err)

	acc := account.NewAccount()
	// TODO: currently the credential is not validated in any form since it's structure is not yet decided on;
	// once that is changed, make sure to update the test
	cred := []byte("foo")
	msg := make([]byte, len(acc.PublicKey)+len(cred))
	copy(msg, acc.PublicKey)
	copy(msg[len(acc.PublicKey):], cred)
	sig := acc.PrivateKey.SignBytes(msg)

	invalidSig := make([]byte, len(sig))
	copy(invalidSig, sig)
	invalidSig[42] ^= byte(0x01)

	invalidPub := make([]byte, len(acc.PublicKey))

	var compressedKey account.ECPublicKey = make([]byte, len(acc.PublicKey))
	copy(compressedKey, acc.PublicKey)
	compressedKey.Compress()

	invalidPubReq, err := proto.Marshal(&transaction.NewAccountRequest{
		PublicKey:  invalidPub,
		Sig:        sig,
		Credential: cred,
	})
	assert.Nil(t, err)

	// it's invalid as signature was created on message involving uncompressed key; if it was done on compressed one,
	// the request would have been valid
	compressedPubReq, err := proto.Marshal(&transaction.NewAccountRequest{
		PublicKey:  compressedKey,
		Sig:        sig,
		Credential: cred,
	})
	assert.Nil(t, err)

	invalidSigReq, err := proto.Marshal(&transaction.NewAccountRequest{
		PublicKey:  acc.PublicKey,
		Sig:        invalidSig,
		Credential: cred,
	})
	assert.Nil(t, err)

	noPubReq, err := proto.Marshal(&transaction.NewAccountRequest{
		PublicKey:  nil,
		Sig:        sig,
		Credential: cred,
	})
	assert.Nil(t, err)

	noSigReq, err := proto.Marshal(&transaction.NewAccountRequest{
		PublicKey:  acc.PublicKey,
		Sig:        nil,
		Credential: cred,
	})
	assert.Nil(t, err)

	invalidReqs := [][]byte{
		nil,
		[]byte{},
		[]byte("foo"),
		emptyReq,
		invalidPubReq,
		compressedPubReq,
		invalidSigReq,
		noPubReq,
		noSigReq,
	}

	validReqTx, err := transaction.CreateNewAccountRequest(acc, []byte{})
	assert.Nil(t, err)
	validReq := validReqTx[1:] // first byte is the prefix indicating type of tx

	acc2 := account.NewAccount()
	acc2.PublicKey.Compress()
	validReqTx2, err := transaction.CreateNewAccountRequest(acc2, []byte{})
	assert.Nil(t, err)
	validReq2 := validReqTx2[1:]

	for _, invalidReq := range invalidReqs {
		assert.NotEqual(t, code.OK, app.checkNewAccountTx(invalidReq))
	}

	for _, validReq := range [][]byte{validReq, validReq2} {
		assert.Equal(t, code.OK, app.checkNewAccountTx(validReq))
	}
}

func TestCheckTransferBetweenAccountsTx(t *testing.T) {
	// no need for checking if transaction amount is valid or accounts exist -> that's done by test for validateTransfer
	emptyReq, err := proto.Marshal(&transaction.AccountTransferRequest{})
	assert.Nil(t, err)

	acc := account.NewAccount()
	target := account.NewAccount().PublicKey

	msg := make([]byte, len(acc.PublicKey)+len(target)+8)
	copy(msg, acc.PublicKey)
	copy(msg[len(acc.PublicKey):], target)
	binary.BigEndian.PutUint64(msg[len(acc.PublicKey)+len(target):], 42)

	sig := acc.PrivateKey.SignBytes(msg)

	invalidSig := make([]byte, len(sig))
	copy(invalidSig, sig)
	invalidSig[42] ^= byte(0x01)

	invalidPub := make([]byte, len(acc.PublicKey))

	var compressedKey account.ECPublicKey = make([]byte, len(acc.PublicKey))
	copy(compressedKey, acc.PublicKey)
	compressedKey.Compress()

	invalidTarget := make([]byte, len(target))
	copy(invalidTarget, target)
	invalidTarget[42] ^= 1

	existingTarget := account.NewAccount().PublicKey
	app.createNewAccountOp(existingTarget)

	invalidPubReq, err := proto.Marshal(&transaction.AccountTransferRequest{
		SourcePublicKey: invalidPub,
		Sig:             sig,
		Amount:          42,
		TargetPublicKey: target,
	})
	assert.Nil(t, err)

	compressedPubReq, err := proto.Marshal(&transaction.AccountTransferRequest{
		SourcePublicKey: compressedKey,
		Sig:             sig,
		Amount:          42,
		TargetPublicKey: target,
	})
	assert.Nil(t, err)

	invalidSigReq, err := proto.Marshal(&transaction.AccountTransferRequest{
		SourcePublicKey: acc.PublicKey,
		Sig:             invalidSig,
		Amount:          42,
		TargetPublicKey: existingTarget,
	})
	assert.Nil(t, err)

	invalidTargetReq, err := proto.Marshal(&transaction.AccountTransferRequest{
		SourcePublicKey: acc.PublicKey,
		Sig:             sig,
		Amount:          42,
		TargetPublicKey: invalidTarget,
	})
	assert.Nil(t, err)

	noPubReq, err := proto.Marshal(&transaction.AccountTransferRequest{
		SourcePublicKey: nil,
		Sig:             sig,
		Amount:          42,
		TargetPublicKey: target,
	})
	assert.Nil(t, err)

	noSigReq, err := proto.Marshal(&transaction.AccountTransferRequest{
		SourcePublicKey: acc.PublicKey,
		Sig:             nil,
		Amount:          42,
		TargetPublicKey: target,
	})
	assert.Nil(t, err)

	noTargetReq, err := proto.Marshal(&transaction.AccountTransferRequest{
		SourcePublicKey: acc.PublicKey,
		Sig:             sig,
		Amount:          42,
		TargetPublicKey: nil,
	})
	assert.Nil(t, err)

	invalidReqs := [][]byte{
		nil,
		[]byte{},
		[]byte("foo"),
		emptyReq,
		invalidPubReq,
		compressedPubReq,
		invalidSigReq,
		invalidTargetReq,
		noPubReq,
		noSigReq,
		noTargetReq,
	}

	validReqTx, err := transaction.CreateNewTransferRequest(acc, target, 42)
	assert.Nil(t, err)
	validReq := validReqTx[1:] // first byte is the prefix indicating type of tx

	balance := make([]byte, 8)
	binary.BigEndian.PutUint64(balance, 1000)
	acc.PublicKey.Compress()
	app.state.db.Set(prefixKey(accountsPrefix, acc.PublicKey), balance)

	for _, invalidReq := range append(invalidReqs, validReq) {
		assert.NotEqual(t, code.OK, app.checkTransferBetweenAccountsTx(invalidReq))
	}

	// not 'validReq' should actually be valid
	app.createNewAccountOp(target)

	for _, validReq := range [][]byte{validReq} {
		assert.Equal(t, code.OK, app.checkTransferBetweenAccountsTx(validReq))
	}
}

// TODO: more tests are more checks are written
