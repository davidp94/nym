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
	"math"
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
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
	app.state.db.Set(prefixKey(tmconst.AccountsPrefix, acc1), balance)

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
	app.state.db.Set(prefixKey(tmconst.AccountsPrefix, acc.PublicKey), balance)

	for _, invalidReq := range append(invalidReqs, validReq) {
		assert.NotEqual(t, code.OK, app.checkTransferBetweenAccountsTx(invalidReq))
	}

	// not 'validReq' should actually be valid
	app.createNewAccountOp(target)

	for _, validReq := range [][]byte{validReq} {
		assert.Equal(t, code.OK, app.checkTransferBetweenAccountsTx(validReq))
	}
}

func copybyteslice(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func copysliceofbytes(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range out {
		out[i] = make([]byte, len(in[i]))
		copy(out[i], in[i])
	}
	return out
}

func deepCopyTransferToHoldingRequest(req *transaction.TransferToHoldingRequest) *transaction.TransferToHoldingRequest {
	enccpy := make([]*elgamal.ProtoEncryption, len(req.Lambda.Enc))
	for i := range enccpy {
		enccpy[i] = &elgamal.ProtoEncryption{}
		enccpy[i].C1 = copybyteslice(req.Lambda.Enc[i].C1)
		enccpy[i].C2 = copybyteslice(req.Lambda.Enc[i].C2)
	}

	return &transaction.TransferToHoldingRequest{
		SourcePublicKey: copybyteslice(req.SourcePublicKey),
		TargetAddress:   copybyteslice(req.TargetAddress),
		Amount:          req.Amount,
		EgPub: &elgamal.ProtoPublicKey{
			P:     copybyteslice(req.EgPub.P),
			G:     copybyteslice(req.EgPub.G),
			Gamma: copybyteslice(req.EgPub.Gamma),
		},
		Lambda: &coconut.ProtoLambda{
			Cm:  copybyteslice(req.Lambda.Cm),
			Enc: enccpy,
			Proof: &coconut.ProtoSignerProof{
				C:  copybyteslice(req.Lambda.Proof.C),
				Rr: copybyteslice(req.Lambda.Proof.Rr),
				Rk: copysliceofbytes(req.Lambda.Proof.Rk),
				Rm: copysliceofbytes(req.Lambda.Proof.Rm),
			},
		},
		PubM: copysliceofbytes(req.PubM),
		Sig:  copybyteslice(req.Sig),
	}
}

func createValidSigOnTransferToHoldingRequest(priv account.ECPrivateKey, req *transaction.TransferToHoldingRequest) []byte {
	lambdab, _ := proto.Marshal(req.Lambda)
	egPubb, _ := proto.Marshal(req.EgPub)

	msg := make([]byte, len(req.SourcePublicKey)+len(req.TargetAddress)+4+len(egPubb)+len(lambdab)+constants.BIGLen*len(req.PubM))
	copy(msg, req.SourcePublicKey)
	copy(msg[len(req.SourcePublicKey):], req.TargetAddress)
	binary.BigEndian.PutUint32(msg[len(req.SourcePublicKey)+len(req.TargetAddress):], uint32(req.Amount))
	copy(msg[len(req.SourcePublicKey)+len(req.TargetAddress)+4:], egPubb)
	copy(msg[len(req.SourcePublicKey)+len(req.TargetAddress)+4+len(egPubb):], lambdab)
	for i := range req.PubM {
		copy(msg[len(req.SourcePublicKey)+len(req.TargetAddress)+4+len(egPubb)+len(lambdab)+constants.BIGLen*i:], req.PubM[i])
	}

	return priv.SignBytes(msg)
}

func TestCheckTransferToHolding(t *testing.T) {
	params, _ := coconut.Setup(5)
	p, rng := params.P(), params.G.Rng()
	s := Curve.Randomnum(p, rng)
	k := Curve.Randomnum(p, rng)

	acc := account.NewAccount()

	_, egPub := elgamal.Keygen(bpgroup.New())
	lambda, err := coconut.PrepareBlindSign(params, egPub, []*Curve.BIG{Curve.NewBIGint(42)}, []*Curve.BIG{s, k})
	assert.Nil(t, err)

	balance := make([]byte, 8)
	binary.BigEndian.PutUint64(balance, math.MaxUint64)
	var accpubcpy account.ECPublicKey = make([]byte, constants.ECPLenUC)
	copy(accpubcpy, acc.PublicKey)
	accpubcpy.Compress()
	app.state.db.Set(prefixKey(tmconst.AccountsPrefix, accpubcpy), balance)

	// create the holding account
	app.state.db.Set(prefixKey(tmconst.AccountsPrefix, tmconst.HoldingAccountAddress), make([]byte, 8))

	// create an existing account
	acc2 := account.NewAccount()
	balance = make([]byte, 8)
	binary.BigEndian.PutUint64(balance, 42)
	acc2.PublicKey.Compress()
	app.state.db.Set(prefixKey(tmconst.AccountsPrefix, acc2.PublicKey), balance)

	reqParams := transaction.TransferToHoldingRequestParams{
		Acc:    acc,
		Amount: int32(42),
		EgPub:  egPub,
		Lambda: lambda,
		PubM:   []*Curve.BIG{Curve.NewBIGint(42)},
	}

	// create a valid request and start malform it in diffent ways
	validReqTx, err := transaction.CreateNewTransferToHoldingRequest(reqParams)
	assert.Nil(t, err)
	validReq := validReqTx[1:] // first byte is the prefix indicating type of tx

	rawReq := &transaction.TransferToHoldingRequest{}
	assert.Nil(t, proto.Unmarshal(validReq, rawReq))

	// firstly check if valid requests go through
	assert.Equal(t, code.OK, app.checkTxTransferToHolding(validReq))

	compKeyReq := deepCopyTransferToHoldingRequest(rawReq)
	compKeyReq.SourcePublicKey = accpubcpy // the key was compressed
	compKeyReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, compKeyReq)

	req, err := proto.Marshal(compKeyReq)
	assert.Nil(t, err)
	assert.Equal(t, code.OK, app.checkTxTransferToHolding(req))

	maxInt32Req := deepCopyTransferToHoldingRequest(rawReq)
	maxInt32Req.Amount = math.MaxInt32
	maxint32BIG := Curve.NewBIGint(int(math.MaxInt32))
	b := make([]byte, constants.BIGLen)
	maxint32BIG.ToBytes(b)
	maxInt32Req.PubM[0] = b
	maxInt32Req.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, maxInt32Req)

	req, err = proto.Marshal(maxInt32Req)
	assert.Nil(t, err)
	assert.Equal(t, code.OK, app.checkTxTransferToHolding(req))

	zeroValReq := deepCopyTransferToHoldingRequest(rawReq)
	zeroValReq.Amount = 0
	zeroBIG := Curve.NewBIGint(0)
	b = make([]byte, constants.BIGLen)
	zeroBIG.ToBytes(b)
	zeroValReq.PubM[0] = b
	zeroValReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, zeroValReq)

	req, err = proto.Marshal(zeroValReq)
	assert.Nil(t, err)
	assert.Equal(t, code.OK, app.checkTxTransferToHolding(req))

	//
	// invalid requests
	//

	noSourceReq := deepCopyTransferToHoldingRequest(rawReq)
	noSourceReq.SourcePublicKey = nil
	noSourceReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, noSourceReq)

	invalidSourceReq := deepCopyTransferToHoldingRequest(rawReq)
	invalidSourceReq.SourcePublicKey = acc2.PublicKey
	invalidSourceReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, invalidSourceReq)

	noTargetReq := deepCopyTransferToHoldingRequest(rawReq)
	noTargetReq.TargetAddress = nil
	noTargetReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, noTargetReq)

	invalidTargetReq := deepCopyTransferToHoldingRequest(rawReq)
	invalidTargetReq.TargetAddress = acc2.PublicKey // so that validate transfer wouldn't fail (acc technically exists)
	invalidTargetReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, invalidTargetReq)

	noEgPubReq := deepCopyTransferToHoldingRequest(rawReq)
	noEgPubReq.EgPub = nil
	noEgPubReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, noEgPubReq)

	invalidEgPubReq := deepCopyTransferToHoldingRequest(rawReq)
	invalidEgPubReq.EgPub.Gamma = []byte("Dummy string converted to bytes")
	invalidEgPubReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, invalidEgPubReq)

	noLambdaReq := deepCopyTransferToHoldingRequest(rawReq)
	noLambdaReq.Lambda = nil
	noLambdaReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, noLambdaReq)

	invalidLambdaReq := deepCopyTransferToHoldingRequest(rawReq)
	invalidLambdaReq.Lambda.Proof.Rr = []byte("Dummy string converted to bytes")
	invalidLambdaReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, invalidLambdaReq)

	noPubMReq := deepCopyTransferToHoldingRequest(rawReq)
	noPubMReq.PubM = nil
	noPubMReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, noPubMReq)

	invalidPubMReq := deepCopyTransferToHoldingRequest(rawReq)
	invalidPubMReq.PubM[0] = []byte("Dummy string converted to bytes")
	invalidPubMReq.Sig = createValidSigOnTransferToHoldingRequest(acc.PrivateKey, invalidPubMReq)

	noSigReq := deepCopyTransferToHoldingRequest(rawReq)
	noSigReq.Sig = nil

	invalidSigReq := deepCopyTransferToHoldingRequest(rawReq)
	invalidSigReq.Sig[42] &= 1

	invalidReqs := []proto.Message{
		noSourceReq,
		invalidSourceReq,
		noTargetReq,
		invalidTargetReq,
		noEgPubReq,
		invalidEgPubReq,
		noLambdaReq,
		invalidLambdaReq,
		noPubMReq,
		invalidPubMReq,
		noSigReq,
		invalidSigReq,
	}

	for _, reqraw := range invalidReqs {
		req, err := proto.Marshal(reqraw)
		assert.Nil(t, err)
		assert.NotEqual(t, code.OK, app.checkTxTransferToHolding(req))
	}

}

func TestCheckDepositCoconutCredentialTx(t *testing.T) {
	emptyReq, err := proto.Marshal(&transaction.DepositCoconutCredentialRequest{})
	assert.Nil(t, err)

	_ = emptyReq

}

// TODO: more tests are more checks are written
