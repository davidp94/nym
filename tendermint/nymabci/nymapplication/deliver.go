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
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
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

func (app *NymApplication) handleDepositCredential(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.DepositCoconutCredentialRequest{}

	if err := proto.Unmarshal(reqb, req); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	if checkResult := app.checkDepositCoconutCredentialTx(reqb); checkResult != code.OK {
		app.log.Info("handleDepositCredential failed checkTx")
		return types.ResponseDeliverTx{Code: checkResult}
	}

	// the errors were checked at checkDepositCoconutCredentialTx call, so they can't by anything else but nil
	// if it's not the case, we can't trust anything that is happening anyway so we can only panic
	cred := &coconut.Signature{}
	theta := &coconut.ThetaTumbler{}
	pubM, err := coconut.BigSliceFromByteSlices(req.PubM)
	mustNilErr(err)
	mustNilErr(cred.FromProto(req.Sig))
	mustNilErr(theta.FromProto(req.Theta))

	address := ethcommon.BytesToAddress(req.ProviderAddress)

	if !app.checkIfAccountExists(address[:]) {
		// if it doesn't exist we know the flag is set to create new account on deposit,
		// otherwise checkTx would have failed
		didSucceed := app.createNewAccountOp(address)
		if !didSucceed {
			app.log.Error("Could not create account for the provider")
			return types.ResponseDeliverTx{Code: code.INVALID_MERCHANT_ADDRESS}
		}
		app.log.Debug(fmt.Sprintf("Created new account for %v", address.Hex()))
	}
	//
	// Once verification is moved to separate entity, the below will be used
	//
	// protoSigB, err := proto.Marshal(req.Sig)
	// if err != nil {
	// 	app.log.Error("Failed to marshal the received credential")
	// 	return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	// }
	// protoThetaB, err := proto.Marshal(req.Theta)
	// if err != nil {
	// 	app.log.Error("Failed to marshal the received crypto materials")
	// 	return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	// }
	// key := make([]byte, ethcommon.AddressLength + len(protoSigB) + len(tmconst.RedeemTokensRequestKeyPrefix))
	// i := copy(key, tmconst.RedeemTokensRequestKeyPrefix)
	// i += copy(key[i:], address)
	// copy(key[i:], protoSigB)
	// return types.ResponseDeliverTx{
	// 	Code: code.OK,
	// 	Tags: []cmn.KVPair{
	// 		// [ Prefix || Provider || credential --- required crypto materials ]
	// 		{Key: key, Value: protoThetaB},
	// 	},
	// }

	// everything below this line will be moved to separate entity (in a way) it will be replaced by the commneted
	// code above
	//
	//
	// =======================================================================================================
	//
	//
	// TODO: credential and proof verification will be moved to another 'verifier' entity
	// but for test sake, let's just leave them here for a time being.
	avk, err := app.retrieveAggregateVerificationKey()
	if err != nil {
		app.log.Error("Failed to retrieve verification key")
		return types.ResponseDeliverTx{Code: code.UNKNOWN}
	}

	// NOTE: TODO:
	// if credentials were to be verified during delivertx rather than by separate entity, there's no
	// point in generating those params every deliverTx. Just store them in state and generate them every time
	// server restarts (or they are nil)
	params := app.getSimpleCoconutParams()
	if params == nil {
		app.log.Error("Failed to generate coconut params")
		return types.ResponseDeliverTx{Code: code.UNKNOWN}
	}
	// verify the credential
	isValid := coconut.BlindVerifyTumbler(params, avk, cred, theta, pubM, address[:])

	if isValid {
		app.log.Debug("The received credential was valid")
		if err := app.increaseBalanceBy(address[:], uint64(req.Value)); err != nil {
			app.log.Error("failed to increase provider's balance? Critical failure")
			panic(err)
		}
		// store the used credential
		app.storeSpentZeta(req.Theta.Zeta)
		return types.ResponseDeliverTx{Code: code.OK}
	}

	app.log.Debug("The received credential was invalid")
	return types.ResponseDeliverTx{Code: code.INVALID_CREDENTIAL}
}
