// deliver.go - DeliverTx-related logic for Tendermint ABCI for Nym
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

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	proto "github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/tendermint/tendermint/abci/types"
	cmn "github.com/tendermint/tendermint/libs/common"
)

const (
	startingBalance uint64 = 0 // this is for purely debug purposes. It will always be 0
)

// tx prefix was already removed
func (app *NymApplication) createNewAccount(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.NewAccountRequest{}

	if err := proto.Unmarshal(reqb, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	var publicKey account.ECPublicKey = req.PublicKey

	if (len(req.PublicKey) != account.PublicKeyUCSize && len(req.PublicKey) != account.PublicKeySize) ||
		len(req.Sig) != account.SignatureSize {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	if !app.verifyCredential(req.Credential) {
		app.log.Info("Failed to verify IP credential")
		return types.ResponseDeliverTx{Code: code.INVALID_CREDENTIAL}
	}

	msg := make([]byte, len(req.PublicKey)+len(req.Credential))
	copy(msg, req.PublicKey)
	copy(msg[len(req.PublicKey):], req.Credential)

	if !publicKey.VerifyBytes(msg, req.Sig) {
		app.log.Info("Failed to verify signature on request")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	didSucceed := app.createNewAccountOp(publicKey)
	if didSucceed {
		return types.ResponseDeliverTx{Code: code.OK}
	}
	return types.ResponseDeliverTx{Code: code.UNKNOWN}
}

// Currently and possibly only for debug purposes
// to freely transfer tokens between accounts to setup different scenarios.
func (app *NymApplication) transferFunds(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.AccountTransferRequest{}

	if err := proto.Unmarshal(reqb, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	var sourcePublicKey account.ECPublicKey = req.SourcePublicKey
	var targetPublicKey account.ECPublicKey = req.TargetPublicKey

	if retCode, data := app.validateTransfer(sourcePublicKey, targetPublicKey, req.Amount); retCode != code.OK {
		return types.ResponseDeliverTx{Code: retCode, Data: data}
	}

	amountB := make([]byte, 8)
	binary.BigEndian.PutUint64(amountB, req.Amount)

	msg := make([]byte, len(sourcePublicKey)+len(targetPublicKey)+8)
	copy(msg, sourcePublicKey)
	copy(msg[len(sourcePublicKey):], targetPublicKey)
	copy(msg[len(sourcePublicKey)+len(targetPublicKey):], amountB)

	if !sourcePublicKey.VerifyBytes(msg, req.Sig) {
		app.log.Info("Failed to verify signature on request")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	retCode, data := app.transferFundsOp(sourcePublicKey, targetPublicKey, req.Amount)

	return types.ResponseDeliverTx{Code: retCode, Data: data}
}

func (app *NymApplication) depositCoconutCredential(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.DepositCoconutCredentialRequest{}

	if err := proto.Unmarshal(reqb, req); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	var merchantAddress account.ECPublicKey = req.MerchantAddress

	// start with checking for double spending -
	// if credential was already spent, there is no point in any further checks
	dbZetaEntry := prefixKey(tmconst.SpentZetaPrefix, req.Theta.Zeta)
	_, zetaStatus := app.state.db.Get(dbZetaEntry)
	if zetaStatus != nil {
		return types.ResponseDeliverTx{Code: code.DOUBLE_SPENDING_ATTEMPT}
	}

	cred := &coconut.Signature{}
	if err := cred.FromProto(req.Sig); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	theta := &coconut.ThetaTumbler{}
	if err := theta.FromProto(req.Theta); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	pubM := coconut.BigSliceFromByteSlices(req.PubM)
	if !coconut.ValidateBigSlice(pubM) {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	// check if the merchant address is correctly formed
	if err := merchantAddress.Compress(); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_MERCHANT_ADDRESS}
	}

	if !app.checkIfAccountExists(merchantAddress) {
		if !createAccountOnDepositIfDoesntExist {
			app.log.Error("Merchant's account doesnt exist")
			return types.ResponseDeliverTx{Code: code.MERCHANT_DOES_NOT_EXIST}
		}

		didSucceed := app.createNewAccountOp(merchantAddress)
		if !didSucceed {
			app.log.Error("Could not create account for the merchant")
			return types.ResponseDeliverTx{Code: code.INVALID_MERCHANT_ADDRESS}
		}
	}

	_, avkb := app.state.db.Get(tmconst.AggregateVkKey)
	avk := &coconut.VerificationKey{}
	if err := avk.UnmarshalBinary(avkb); err != nil {
		app.log.Error("Failed to unarsmahl vk...")
		return types.ResponseDeliverTx{Code: code.UNKNOWN}
	}

	// basically gets params without bpgroup
	params := app.getSimpleCoconutParams()
	// verify the credential
	isValid := coconut.BlindVerifyTumbler(params, avk, cred, theta, pubM, merchantAddress)

	if isValid {
		retCode, data := app.transferFundsOp(tmconst.HoldingAccountAddress, merchantAddress, uint64(req.Value))
		// store the used credential
		app.state.db.Set(dbZetaEntry, tmconst.SpentZetaPrefix)
		return types.ResponseDeliverTx{Code: retCode, Data: data}
	}
	return types.ResponseDeliverTx{Code: code.INVALID_CREDENTIAL}
}

// transfers funds from the given user's account to the holding account. It makes sure it's only done once per
// particular credential request.
// TODO: wait on deicison on implementation
func (app *NymApplication) transferToHolding(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.TransferToHoldingRequest{}
	if err := proto.Unmarshal(reqb, req); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	if len(req.PubM) < 1 ||
		len(req.PubM[0]) != constants.BIGLen ||
		Curve.Comp(Curve.FromBytes(req.PubM[0]), Curve.NewBIGint(int(req.Amount))) != 0 {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	// only recovered to see if an error is thrown
	lambda := &coconut.Lambda{}
	if err := lambda.FromProto(req.Lambda); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	lambdab, err := proto.Marshal(req.Lambda)
	if err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	// only recovered to see if an error is thrown
	egPub := &elgamal.PublicKey{}
	if err := egPub.FromProto(req.EgPub); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	egPubb, err := proto.Marshal(req.EgPub)
	if err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	var sourcePublicKey account.ECPublicKey = req.SourcePublicKey
	recoveredHoldingAddress := req.TargetAddress

	// TODO: update once epochs, etc. are introduced
	if bytes.Compare(recoveredHoldingAddress, tmconst.HoldingAccountAddress) != 0 {
		return types.ResponseDeliverTx{Code: code.MALFORMED_ADDRESS}
	}

	if retCode, data := app.validateTransfer(sourcePublicKey, recoveredHoldingAddress, uint64(req.Amount)); retCode != code.OK {
		return types.ResponseDeliverTx{Code: retCode, Data: data}
	}

	msg := make([]byte, len(sourcePublicKey)+len(recoveredHoldingAddress)+4+len(egPubb)+len(lambdab)+constants.BIGLen*len(req.PubM))
	copy(msg, sourcePublicKey)
	copy(msg[len(sourcePublicKey):], recoveredHoldingAddress)
	binary.BigEndian.PutUint32(msg[len(sourcePublicKey)+len(recoveredHoldingAddress):], uint32(req.Amount))
	copy(msg[len(sourcePublicKey)+len(recoveredHoldingAddress)+4:], egPubb)
	copy(msg[len(sourcePublicKey)+len(recoveredHoldingAddress)+4+len(egPubb):], lambdab)
	for i := range req.PubM {
		copy(msg[len(sourcePublicKey)+len(recoveredHoldingAddress)+4+len(egPubb)+len(lambdab)+constants.BIGLen*i:], req.PubM[i])
	}

	if len(req.Sig) != account.SignatureSize || !sourcePublicKey.VerifyBytes(msg, req.Sig) {
		app.log.Info("Failed to verify signature on request")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	retCode, data := app.transferFundsOp(sourcePublicKey, recoveredHoldingAddress, uint64(req.Amount))
	if retCode == code.OK {
		// lambda, egpub, pubm
		blindSignMaterials := &coconut.BlindSignMaterials{
			Lambda: req.Lambda,
			EgPub:  req.EgPub,
			PubM:   req.PubM,
		}

		bsmb, err := proto.Marshal(blindSignMaterials)
		if err != nil {
			// it's really impossible for this to fail, but if it somehow does, it's client's fault for providing
			// such weirdly malformed data
			app.log.Error("Proto error after transfer already occured")
			// TODO: possibly revert operation?
			return types.ResponseDeliverTx{Code: code.UNKNOWN}
		}

		sourcePublicKey.Compress()
		return types.ResponseDeliverTx{Code: retCode, Data: data, Tags: []cmn.KVPair{{Key: sourcePublicKey, Value: bsmb}}}
	}
	return types.ResponseDeliverTx{Code: retCode, Data: data}
}

// req := &transaction.TransferToHoldingRequest{}

// if err := proto.Unmarshal(reqb, req); err != nil {
// 	return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// }

// var sourcePublicKey account.ECPublicKey = req.SourcePublicKey
// recoveredHoldingAddress := req.TargetAddress

// // TODO: update once epochs, etc. are introduced
// if bytes.Compare(recoveredHoldingAddress, tmconst.HoldingAccountAddress) != 0 {
// 	return types.ResponseDeliverTx{Code: code.MALFORMED_ADDRESS, Data: []byte("HOLDING")}
// }
// if retCode, data := app.validateTransfer(sourcePublicKey, recoveredHoldingAddress, uint64(req.Amount)); retCode != code.OK {
// 	return types.ResponseDeliverTx{Code: retCode, Data: data}
// }

// msg := make([]byte, len(req.SourcePublicKey)+len(req.TargetAddress)+4+len(req.Nonce))
// copy(msg, req.SourcePublicKey)
// copy(msg[len(req.SourcePublicKey):], req.TargetAddress)
// binary.BigEndian.PutUint32(msg[len(req.SourcePublicKey)+len(req.TargetAddress):], req.Amount)
// copy(msg[len(req.SourcePublicKey)+len(req.TargetAddress)+4:], req.Nonce)

// if !sourcePublicKey.VerifyBytes(msg, req.Sig) {
// 	app.log.Info("Failed to verify signature on request")
// 	return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
// }

// retCode, data := app.transferFundsOp(sourcePublicKey, recoveredHoldingAddress, uint64(req.Amount))
// if retCode == code.OK {
// 	// it can't fail as transferFunds already performed it
// 	sourcePublicKey.Compress()
// 	amountB := make([]byte, 4)
// 	binary.BigEndian.PutUint32(amountB, req.Amount)
// 	// only include tags if tx was successful
// 	key := make([]byte, len(sourcePublicKey)+len(req.Nonce))
// 	copy(key, sourcePublicKey)
// 	copy(key[len(sourcePublicKey):], req.Nonce)
// 	return types.ResponseDeliverTx{Code: retCode, Data: data, Tags: []cmn.KVPair{{Key: key, Value: amountB}}}
// }
// return types.ResponseDeliverTx{Code: retCode, Data: data}
// }

// old implementation, if initiated by IAs:
// var IAPub account.ECPublicKey
// var clientPub account.ECPublicKey

// req := &transaction.TransferToHoldingRequest{}
// if err := proto.Unmarshal(reqb, req); err != nil {
// 	return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// }

// idb := make([]byte, 4)
// binary.BigEndian.PutUint32(idb, req.IAID)
// dbEntry := prefixKey(tmconst.IaKeyPrefix, idb)
// _, IAPubb := app.state.db.Get(dbEntry)

// // check if IA exists
// if IAPubb == nil {
// 	return types.ResponseDeliverTx{Code: code.ISSUING_AUTHORITY_DOES_NOT_EXIST}
// }

// IAPub = IAPubb
// clientPub = req.ClientPublicKey

// // error would be returned if address is malformed
// if err := clientPub.Compress(); err != nil {
// 	return types.ResponseDeliverTx{Code: code.MALFORMED_ADDRESS, Data: []byte("CLIENT")}
// }

// // Verify both sigs
// clientMsg := make([]byte, len(req.ClientPublicKey)+4+len(req.Commitment))
// copy(clientMsg, req.ClientPublicKey) // copy the original one in case the signature was on uncompressed key
// binary.BigEndian.PutUint32(clientMsg[len(req.ClientPublicKey):], uint32(req.Amount))
// copy(clientMsg[len(req.ClientPublicKey)+4:], req.Commitment)

// if !clientPub.VerifyBytes(clientMsg, req.ClientSig) {
// 	return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE, Data: []byte("CLIENT")}
// }

// msg := make([]byte, 4+len(clientMsg)+len(req.ClientSig))
// copy(msg, idb)
// copy(msg[4:], clientMsg)
// copy(msg[4+len(clientMsg):], req.ClientSig)

// if !IAPub.VerifyBytes(msg, req.IASig) {
// 	return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE, Data: []byte("ISSUING AUTHORITY")}
// }

// // if cm wasn't seen before check balance and do the transfer
// // else return the same error code as before  - to prevent inconsistency, ex:
// // block N - IA1 sends the request - it fails due to insufficient funds
// // block N+1 - client's funds are increased somehow or his account is now created, etc
// // block N+2 - another IA sends the request

// dbKey := prefixKey(tmconst.CommitmentsPrefix, req.Commitment)
// _, previousCode := app.state.db.Get(dbKey)
// if previousCode != nil {
// 	// another IA already sent the request before - we return the same result
// 	app.log.Info("This request was already completed")
// 	return types.ResponseDeliverTx{Code: binary.BigEndian.Uint32(previousCode), Data: []byte("DUPLICATE")}
// }

// retCodeB := make([]byte, 4)

// // check if client exists and has sufficient balance to actually transfer
// clientBalanceB, retCode := app.queryBalance(clientPub)
// if retCode != code.OK {
// 	binary.BigEndian.PutUint32(retCodeB, retCode)
// 	app.state.db.Set(dbKey, retCodeB)
// 	return types.ResponseDeliverTx{Code: code.ACCOUNT_DOES_NOT_EXIST}
// }

// // balance is actually also checked when transferring funds, but since we have to query db to check if
// // the account exists, we might as well get the balance and possibly terminate earlier if it's invalid
// // so that we would not have to verify the below signatures
// clientBalance := binary.BigEndian.Uint64(clientBalanceB)
// if clientBalance < uint64(req.Amount) {
// 	binary.BigEndian.PutUint32(retCodeB, code.INSUFFICIENT_BALANCE)
// 	app.state.db.Set(dbKey, retCodeB)
// 	return types.ResponseDeliverTx{Code: code.INSUFFICIENT_BALANCE}
// }

// // the request is valid, so transfer the amount
// transferRetCode, data := app.transferFundsOp(clientPub, tmconst.HoldingAccountAddress, uint64(req.Amount))
// binary.BigEndian.PutUint32(retCodeB, transferRetCode)
// app.state.db.Set(dbKey, retCodeB)

// return types.ResponseDeliverTx{Code: transferRetCode, Data: data}
// }
