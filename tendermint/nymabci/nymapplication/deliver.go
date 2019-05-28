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
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/protobuf/proto"
	"github.com/tendermint/tendermint/abci/types"
)

const (
	startingBalance uint64 = 10 // this is for purely debug purposes. It will always be 0
)

// tx prefix was already removed
func (app *NymApplication) createNewAccount(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.NewAccountRequest{}

	if err := proto.Unmarshal(reqb, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	if len(req.Address) != ethcommon.AddressLength {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	if !app.verifyCredential(req.Credential) {
		app.log.Info("Failed to verify IP credential")
		return types.ResponseDeliverTx{Code: code.INVALID_CREDENTIAL}
	}

	msg := make([]byte, len(req.Address)+len(req.Credential))
	copy(msg, req.Address)
	copy(msg[len(req.Address):], req.Credential)

	recPub, err := ethcrypto.SigToPub(tmconst.HashFunction(msg), req.Sig)
	if err != nil {
		app.log.Info("Error while trying to recover public key associated with the signature")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	recAddr := ethcrypto.PubkeyToAddress(*recPub)
	if !bytes.Equal(recAddr[:], req.Address) {
		app.log.Info("Failed to verify signature on request")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	// we already know recAddr is identical to the address sent
	didSucceed := app.createNewAccountOp(recAddr)
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

	if app.checkNonce(req.Nonce, req.SourceAddress) {
		return types.ResponseDeliverTx{Code: code.REPLAY_ATTACK_ATTEMPT}
	}

	if retCode, _ := app.validateTransfer(req.SourceAddress, req.TargetAddress, req.Amount); retCode != code.OK {
		return types.ResponseDeliverTx{Code: retCode}
	}

	msg := make([]byte, 2*ethcommon.AddressLength+tmconst.NonceLength+8)
	copy(msg, req.SourceAddress)
	copy(msg[ethcommon.AddressLength:], req.TargetAddress)
	binary.BigEndian.PutUint64(msg[2*ethcommon.AddressLength:], req.Amount)
	copy(msg[2*ethcommon.AddressLength+8:], req.Nonce)

	recPub, err := ethcrypto.SigToPub(tmconst.HashFunction(msg), req.Sig)
	if err != nil {
		app.log.Info("Error while trying to recover public key associated with the signature")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	recAddr := ethcrypto.PubkeyToAddress(*recPub)
	if !bytes.Equal(recAddr[:], req.SourceAddress) {
		app.log.Info("Failed to verify signature on request")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	retCode, data := app.transferFundsOp(req.SourceAddress, req.TargetAddress, req.Amount)
	if retCode == code.OK {
		app.setNonce(req.Nonce, req.SourceAddress)
	}
	return types.ResponseDeliverTx{Code: retCode, Data: data}
}

func (app *NymApplication) handleTransferToPipeAccountNotification(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.TransferToPipeAccountNotification{}

	if err := proto.Unmarshal(reqb, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	// first check if the threshold was alredy reached and transaction was committed
	if app.getNotificationCount(req.TxHash) == app.state.watcherThreshold {
		app.log.Info("Already reached required threshold")
		return types.ResponseDeliverTx{Code: code.ALREADY_COMMITTED}
	}

	// check if the watcher can be trusted
	if !app.checkWatcherKey(req.WatcherPublicKey) {
		app.log.Info("This watcher is not in the trusted set")
		return types.ResponseDeliverTx{Code: code.ETHEREUM_WATCHER_DOES_NOT_EXIST}
	}

	// check if client address is correctly formed
	if len(req.ClientAddress) != ethcommon.AddressLength {
		app.log.Info("Client's address is malformed")
		return types.ResponseDeliverTx{Code: code.MALFORMED_ADDRESS}
	}

	// check if the pipe account matches
	if !bytes.Equal(app.state.pipeAccount[:], req.PipeAccountAddress) {
		app.log.Info("The specified pipe account is different from the expected one")
		return types.ResponseDeliverTx{Code: code.INVALID_PIPE_ACCOUNT}
	}

	// check signature
	msg := make([]byte, len(req.WatcherPublicKey)+2*ethcommon.AddressLength+8+ethcommon.HashLength)
	copy(msg, req.WatcherPublicKey)
	copy(msg[len(req.WatcherPublicKey):], req.ClientAddress)
	copy(msg[len(req.WatcherPublicKey)+ethcommon.AddressLength:], req.PipeAccountAddress)
	binary.BigEndian.PutUint64(msg[len(req.WatcherPublicKey)+2*ethcommon.AddressLength:], req.Amount)
	copy(msg[len(req.WatcherPublicKey)+ethcommon.AddressLength+8:], req.TxHash)

	sig := req.Sig
	// last byte is a recoveryID which we don't care about
	if len(sig) > 64 {
		sig = sig[:64]
	}

	if !ethcrypto.VerifySignature(req.WatcherPublicKey, tmconst.HashFunction(msg), sig) {
		app.log.Info("The signature on message is invalid")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	// check if this tx was not already confirmed by this watcher
	if app.checkWatcherNotification(req.WatcherPublicKey, req.TxHash) {
		app.log.Info("This watcher already sent this notification before")
		return types.ResponseDeliverTx{Code: code.ALREADY_CONFIRMED}
	}

	// 'accept' the notification
	newCount := app.storeWatcherNotification(req.WatcherPublicKey, req.TxHash)

	app.log.Debug(fmt.Sprintf("Reached %v notifications out of required %v for %v",
		newCount,
		app.state.watcherThreshold,
		ethcommon.BytesToHash(req.TxHash).Hex(),
	))

	// commit the transaction if threshold is reached
	if newCount == app.state.watcherThreshold {
		app.log.Debug(fmt.Sprintf("Reached required threshold of %v for %v",
			app.state.watcherThreshold,
			ethcommon.BytesToHash(req.TxHash).Hex(),
		))
		// check if account exists
		currentBalance, err := app.retrieveAccountBalance(req.ClientAddress)
		if err != nil && createAccountOnPipeAccountTransferIfDoesntExist {
			didSucceed := app.createNewAccountOp(ethcommon.BytesToAddress(req.ClientAddress))
			if !didSucceed {
				app.log.Info(fmt.Sprintf("Failed to create new account for the client with address %v",
					ethcommon.BytesToAddress(req.ClientAddress).Hex()))
				return types.ResponseDeliverTx{Code: code.UNKNOWN}
			}
		} else if err != nil {
			app.log.Info("Client's account does not exist and system is not set to create new ones")
			return types.ResponseDeliverTx{Code: code.ACCOUNT_DOES_NOT_EXIST}
		}

		app.setAccountBalance(req.ClientAddress, currentBalance+req.Amount)
	}

	return types.ResponseDeliverTx{Code: code.OK}
}

// func (app *NymApplication) depositCoconutCredential(reqb []byte) types.ResponseDeliverTx {
// 	req := &transaction.DepositCoconutCredentialRequest{}

// 	if err := proto.Unmarshal(reqb, req); err != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	var merchantAddress account.ECPublicKey = req.MerchantAddress

// 	// start with checking for double spending -
// 	// if credential was already spent, there is no point in any further checks
// 	dbZetaEntry := prefixKey(tmconst.SpentZetaPrefix, req.Theta.Zeta)
// 	_, zetaStatus := app.state.db.Get(dbZetaEntry)
// 	if zetaStatus != nil {
// 		return types.ResponseDeliverTx{Code: code.DOUBLE_SPENDING_ATTEMPT}
// 	}

// 	cred := &coconut.Signature{}
// 	if err := cred.FromProto(req.Sig); err != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	theta := &coconut.ThetaTumbler{}
// 	if err := theta.FromProto(req.Theta); err != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	pubM := coconut.BigSliceFromByteSlices(req.PubM)
// 	if !coconut.ValidateBigSlice(pubM) {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	// check if the merchant address is correctly formed
// 	if err := merchantAddress.Compress(); err != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_MERCHANT_ADDRESS}
// 	}

// 	if !app.checkIfAccountExists(merchantAddress) {
// 		if !createAccountOnDepositIfDoesntExist {
// 			app.log.Error("Merchant's account doesnt exist")
// 			return types.ResponseDeliverTx{Code: code.MERCHANT_DOES_NOT_EXIST}
// 		}

// 		didSucceed := app.createNewAccountOp(merchantAddress)
// 		if !didSucceed {
// 			app.log.Error("Could not create account for the merchant")
// 			return types.ResponseDeliverTx{Code: code.INVALID_MERCHANT_ADDRESS}
// 		}
// 	}

// 	_, avkb := app.state.db.Get(tmconst.AggregateVkKey)
// 	avk := &coconut.VerificationKey{}
// 	if err := avk.UnmarshalBinary(avkb); err != nil {
// 		app.log.Error("Failed to unarsmahl vk...")
// 		return types.ResponseDeliverTx{Code: code.UNKNOWN}
// 	}

// 	// basically gets params without bpgroup
// 	params := app.getSimpleCoconutParams()
// 	// verify the credential
// 	isValid := coconut.BlindVerifyTumbler(params, avk, cred, theta, pubM, merchantAddress)

// 	if isValid {
// 		retCode, data := app.transferFundsOp(tmconst.PipeAccountAddress, merchantAddress, uint64(req.Value))
// 		// store the used credential
// 		app.state.db.Set(dbZetaEntry, tmconst.SpentZetaPrefix)
// 		return types.ResponseDeliverTx{Code: retCode, Data: data}
// 	}
// 	return types.ResponseDeliverTx{Code: code.INVALID_CREDENTIAL}
// }

// // transfers funds from the given user's account to the pipe account. It makes sure it's only done once per
// // particular credential request.
// // TODO: wait on deicison on implementation
// func (app *NymApplication) transferToPipeAccount(reqb []byte) types.ResponseDeliverTx {
// 	req := &transaction.TransferToPipeAccountRequest{}
// 	if err := proto.Unmarshal(reqb, req); err != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	if len(req.PubM) < 1 ||
// 		len(req.PubM[0]) != constants.BIGLen ||
// 		Curve.Comp(Curve.FromBytes(req.PubM[0]), Curve.NewBIGint(int(req.Amount))) != 0 {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	// only recovered to see if an error is thrown
// 	lambda := &coconut.Lambda{}
// 	if err := lambda.FromProto(req.Lambda); err != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	lambdab, err := proto.Marshal(req.Lambda)
// 	if err != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	// only recovered to see if an error is thrown
// 	egPub := &elgamal.PublicKey{}
// 	if rerr := egPub.FromProto(req.EgPub); rerr != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	egPubb, err := proto.Marshal(req.EgPub)
// 	if err != nil {
// 		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// 	}

// 	var sourcePublicKey account.ECPublicKey = req.SourcePublicKey
// 	recoveredPipeAccountAddress := req.TargetAddress

// 	// TODO: update once epochs, etc. are introduced
// 	if !bytes.Equal(recoveredPipeAccountAddress, tmconst.PipeAccountAddress) {
// 		return types.ResponseDeliverTx{Code: code.MALFORMED_ADDRESS}
// 	}

// 	if retCode, data := app.validateTransfer(sourcePublicKey,
// 		recoveredPipeAccountAddress,
// 		uint64(req.Amount),
// 	); retCode != code.OK {
// 		return types.ResponseDeliverTx{Code: retCode, Data: data}
// 	}

// 	msg := make([]byte,
// 		len(sourcePublicKey)+len(recoveredPipeAccountAddress)+4+len(egPubb)+len(lambdab)+constants.BIGLen*len(req.PubM),
// 	)
// 	copy(msg, sourcePublicKey)
// 	copy(msg[len(sourcePublicKey):], recoveredPipeAccountAddress)
// 	binary.BigEndian.PutUint32(msg[len(sourcePublicKey)+len(recoveredPipeAccountAddress):], uint32(req.Amount))
// 	copy(msg[len(sourcePublicKey)+len(recoveredPipeAccountAddress)+4:], egPubb)
// 	copy(msg[len(sourcePublicKey)+len(recoveredPipeAccountAddress)+4+len(egPubb):], lambdab)
// 	for i := range req.PubM {
// 		copy(msg[len(sourcePublicKey)+len(recoveredPipeAccountAddress)+4+len(egPubb)+len(lambdab)+constants.BIGLen*i:],
// 			req.PubM[i],
// 		)
// 	}

// 	if len(req.Sig) != account.SignatureSize || !sourcePublicKey.VerifyBytes(msg, req.Sig) {
// 		app.log.Info("Failed to verify signature on request")
// 		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
// 	}

// 	retCode, data := app.transferFundsOp(sourcePublicKey, recoveredPipeAccountAddress, uint64(req.Amount))
// 	if retCode == code.OK {
// 		// lambda, egpub, pubm
// 		blindSignMaterials := &coconut.BlindSignMaterials{
// 			Lambda: req.Lambda,
// 			EgPub:  req.EgPub,
// 			PubM:   req.PubM,
// 		}

// 		bsmb, err := proto.Marshal(blindSignMaterials)
// 		if err != nil {
// 			// it's really impossible for this to fail, but if it somehow does, it's client's fault for providing
// 			// such weirdly malformed data
// 			app.log.Error("Proto error after transfer already occurred")
// 			// TODO: possibly revert operation?
// 			return types.ResponseDeliverTx{Code: code.UNKNOWN}
// 		}

// 		// it can't possibly fail as it was already verified
// 		//nolint: errcheck
// 		sourcePublicKey.Compress()
// 		// we need to include slightly more information in the key field in case given user performed
// 		// more than 1 transfer in given block. That way he wouldn't need to recreate bsmb to index the tx
// 		key := make([]byte, len(sourcePublicKey)+constants.ECPLen+len(tmconst.CredentialRequestKeyPrefix))
// 		copy(key, tmconst.CredentialRequestKeyPrefix)
// 		copy(key[len(tmconst.CredentialRequestKeyPrefix):], sourcePublicKey)

// 		// gamma is unique per credential request;
// 		// it's client's fault if he intentionally reuses is and is up to him to distinguish correct credentials
// 		egPub.Gamma().ToBytes((key[len(tmconst.CredentialRequestKeyPrefix)+len(sourcePublicKey):]), true)

// 		return types.ResponseDeliverTx{Code: retCode, Data: data, Tags: []cmn.KVPair{{Key: key, Value: bsmb}}}
// 	}
// 	return types.ResponseDeliverTx{Code: retCode, Data: data}
// }

// req := &transaction.TransferToPipeAccountRequest{}

// if err := proto.Unmarshal(reqb, req); err != nil {
// 	return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
// }

// var sourcePublicKey account.ECPublicKey = req.SourcePublicKey
// recoveredPipeAccountAddress := req.TargetAddress

// // TODO: update once epochs, etc. are introduced
// if bytes.Compare(recoveredPipeAccountAddress, tmconst.PipeAccountAddress) != 0 {
// 	return types.ResponseDeliverTx{Code: code.MALFORMED_ADDRESS, Data: []byte("PIPEACCOUNT")}
// }
// if retCode, data := app.validateTransfer(sourcePublicKey, recoveredPipeAccountAddress, uint64(req.Amount)); retCode != code.OK {
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

// retCode, data := app.transferFundsOp(sourcePublicKey, recoveredPipeAccountAddress, uint64(req.Amount))
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

// req := &transaction.TransferToPipeAccountRequest{}
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
// transferRetCode, data := app.transferFundsOp(clientPub, tmconst.PipeAccountAddress, uint64(req.Amount))
// binary.BigEndian.PutUint32(retCodeB, transferRetCode)
// app.state.db.Set(dbKey, retCodeB)

// return types.ResponseDeliverTx{Code: transferRetCode, Data: data}
// }

// // currently for debug purposes to check if given g^s is in the spent set
// func (app *NymApplication) lookUpZeta(zeta []byte) []byte {
// 	_, val := app.state.db.Get(zeta)

// 	if val != nil {
// 		return []byte{1}
// 	}
// 	return []byte{}
// }
