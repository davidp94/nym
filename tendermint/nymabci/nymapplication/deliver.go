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
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/golang/protobuf/proto"
	"github.com/tendermint/tendermint/abci/types"
	cmn "github.com/tendermint/tendermint/libs/common"
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

	if checkResult := app.checkNewAccountTx(reqb); checkResult != code.OK {
		app.log.Info("CreateNewAccount failed checkTx")
		return types.ResponseDeliverTx{Code: checkResult}
	}

	// we already know recAddr is identical to the address sent
	didSucceed := app.createNewAccountOp(ethcommon.BytesToAddress(req.Address))
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

	if checkResult := app.checkTransferBetweenAccountsTx(reqb); checkResult != code.OK {
		app.log.Info("TransferFunds failed checkTx")
		return types.ResponseDeliverTx{Code: checkResult}
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

	if checkResult := app.checkTransferToPipeAccountNotificationTx(reqb); checkResult != code.OK {
		app.log.Info("HandlePipeTransferNotification failed checkTx")
		return types.ResponseDeliverTx{Code: checkResult}
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

// authorized user to obtain credential - writes crypto materials to the chain and removes his funds
func (app *NymApplication) handleCredentialRequest(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.CredentialRequest{}
	if err := proto.Unmarshal(reqb, req); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	if checkResult := app.checkCredentialRequestTx(reqb); checkResult != code.OK {
		app.log.Info("HandleCredentialRequest failed checkTx")
		return types.ResponseDeliverTx{Code: checkResult}
	}

	cryptoMaterialsBytes, err := proto.Marshal(req.CryptoMaterials)
	if err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	// remove funds
	if err := app.decreaseBalanceBy(req.ClientAddress, uint64(req.Value)); err != nil {
		// it's impossible for it to fail as err is only thrown if account does not exist or has insufficient balance
		// and we already checked for that
		app.log.Error(fmt.Sprintf("Undefined behaviour when trying to decrease client's (%v) balance: %v",
			ethcommon.BytesToAddress(req.ClientAddress).Hex(),
			err,
		))
		// TODO: panic or just continue?
	}

	// we need to include slightly more information in the key field in case given user performed
	// more than 1 transfer in given block. That way he wouldn't need to recreate byte materials to index the tx
	key := make([]byte, ethcommon.AddressLength+constants.ECPLen+len(tmconst.CredentialRequestKeyPrefix))
	i := copy(key, tmconst.CredentialRequestKeyPrefix)
	i += copy(key[i:], req.ClientAddress)
	// gamma is unique per credential request;
	// it's client's fault if he intentionally reuses is and is up to him to distinguish correct credentials
	copy(key[i:], req.CryptoMaterials.EgPub.Gamma)
	return types.ResponseDeliverTx{
		Code: code.OK,
		Tags: []cmn.KVPair{
			{Key: key, Value: cryptoMaterialsBytes},
		},
	}
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
