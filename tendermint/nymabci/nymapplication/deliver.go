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
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	proto "github.com/golang/protobuf/proto"
	"github.com/tendermint/tendermint/abci/types"
)

const (
	startingBalance uint64 = 0 // this is for purely debug purposes. It will always be 0
)

// implementation will be IP-specific
func (app *NymApplication) verifyCredential(cred []byte) bool {
	return true
}

// tx prefix was already removed
func (app *NymApplication) createNewAccount(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.NewAccountRequest{}
	var publicKey account.ECPublicKey

	if err := proto.Unmarshal(reqb, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	if !app.verifyCredential(req.Credential) {
		app.log.Info("Failed to verify IP credential")
		return types.ResponseDeliverTx{Code: code.INVALID_CREDENTIAL}
	}

	publicKey = req.PublicKey

	msg := make([]byte, len(req.PublicKey)+len(req.Credential))
	copy(msg, req.PublicKey)
	copy(msg[len(req.PublicKey):], req.Credential)

	if !publicKey.VerifyBytes(msg, req.Sig) {
		app.log.Info("Failed to verify signature on request")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	// we know public key is valid because otherwise the signature would not have been validated
	// if key is already in its compressed form, the function will just return so there's no harm
	if err := publicKey.Compress(); err != nil {
		app.log.Error("All checks were successful, but failed to compress the key. UNDEFINED BEHAVIOUR")
		return types.ResponseDeliverTx{Code: code.UNKNOWN}
	}

	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, startingBalance)

	dbEntry := prefixKey(accountsPrefix, publicKey)
	app.state.db.Set(dbEntry, value)

	hexname := base64.StdEncoding.EncodeToString(publicKey)
	app.log.Info(fmt.Sprintf("Created new account: %v with starting balance: %v", hexname, startingBalance))

	return types.ResponseDeliverTx{Code: code.OK}
}

// Currently and possibly only for debug purposes
// to freely transfer tokens between accounts to setup different scenarios.
func (app *NymApplication) transferFunds(reqb []byte) types.ResponseDeliverTx {
	req := &transaction.AccountTransferRequest{}
	var sourcePublicKey account.ECPublicKey
	var targetPublicKey account.ECPublicKey

	if err := proto.Unmarshal(reqb, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	sourcePublicKey = req.SourcePublicKey
	targetPublicKey = req.TargetPublicKey
	ammountB := make([]byte, 8)
	binary.BigEndian.PutUint64(ammountB, req.Ammount)

	msg := make([]byte, len(sourcePublicKey)+len(targetPublicKey)+8)
	copy(msg, sourcePublicKey)
	copy(msg[len(sourcePublicKey):], targetPublicKey)
	copy(msg[len(sourcePublicKey)+len(targetPublicKey):], ammountB)

	if !sourcePublicKey.VerifyBytes(msg, req.Sig) {
		app.log.Info("Failed to verify signature on request")
		return types.ResponseDeliverTx{Code: code.INVALID_SIGNATURE}
	}

	sourcePublicKey.Compress()
	sourceBalanceB, retCode := app.queryBalance(sourcePublicKey)
	if retCode != code.OK {
		return types.ResponseDeliverTx{Code: retCode} // among other things checks if the source account exists
	}

	sourceBalance := binary.BigEndian.Uint64(sourceBalanceB)
	ammount := binary.BigEndian.Uint64(ammountB)
	if sourceBalance < ammount { // + some gas?
		return types.ResponseDeliverTx{Code: code.INSUFFICIENT_BALANCE}
	}

	targetPublicKey.Compress()
	targetBalanceB, retCodeT := app.queryBalance(targetPublicKey)
	if retCodeT != code.OK {
		return types.ResponseDeliverTx{Code: retCodeT} // among other things checks if the source account exists
	}

	targetBalance := binary.BigEndian.Uint64(targetBalanceB)

	// finally initiate the transfer
	sourceResult := sourceBalance - ammount
	targetResult := targetBalance + ammount

	sourceResultB := make([]byte, 8)
	targetResultB := make([]byte, 8)

	binary.BigEndian.PutUint64(sourceResultB, sourceResult)
	binary.BigEndian.PutUint64(targetResultB, targetResult)

	sourceDbEntry := prefixKey(accountsPrefix, sourcePublicKey)
	app.state.db.Set(sourceDbEntry, sourceResultB)

	targetDbEntry := prefixKey(accountsPrefix, targetPublicKey)
	app.state.db.Set(targetDbEntry, targetResultB)

	app.log.Info(fmt.Sprintf("Transfered %v from %v to %v",
		ammount, base64.StdEncoding.EncodeToString(sourcePublicKey), base64.StdEncoding.EncodeToString(targetPublicKey)))
	return types.ResponseDeliverTx{Code: code.OK}
}

func (app *NymApplication) verifyCoconutCredential(reqb []byte) types.ResponseDeliverTx {
	protoRequest := &transaction.VerifyCoconutCredentialRequest{}
	if err := proto.Unmarshal(reqb, protoRequest); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	cred := &coconut.Signature{}
	if err := cred.FromProto(protoRequest.Sig); err != nil {
		return types.ResponseDeliverTx{Code: code.INVALID_TX_PARAMS}
	}

	pubM := coconut.BigSliceFromByteSlices(protoRequest.PubM)

	_, avkb := app.state.db.Get(aggregateVkKey)
	avk := &coconut.VerificationKey{}
	if err := avk.UnmarshalBinary(avkb); err != nil {
		app.log.Error("Failed to unarsmahl vk...")
		return types.ResponseDeliverTx{Code: code.UNKNOWN}
	}

	params, err := coconut.Setup(1)
	if err != nil {
		app.log.Error("Unexpected error while generating params...")
		return types.ResponseDeliverTx{Code: code.UNKNOWN}
	}
	isValid := coconut.Verify(params, avk, pubM, cred)

	if isValid {
		return types.ResponseDeliverTx{Code: code.OK, Data: transaction.TruthBytes}
	}
	return types.ResponseDeliverTx{Code: code.OK, Data: transaction.FalseBytes}
}
