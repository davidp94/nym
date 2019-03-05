// check.go - CheckTx logic for Tendermint ABCI for Nym
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

	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	proto "github.com/golang/protobuf/proto"
)

func (app *NymApplication) validateTransfer(inAddr, outAddr account.ECPublicKey, amount uint64) (uint32, []byte) {
	// holding account is a special case - it's not an EC point but just a string which is uncompressable
	if bytes.Compare(inAddr, holdingAccountAddress) != 0 {
		if err := inAddr.Compress(); err != nil {
			// 'normal' address is invalid
			return code.MALFORMED_ADDRESS, []byte("SOURCE")
		}
	}
	sourceBalanceB, retCode := app.queryBalance(inAddr)
	if retCode != code.OK {
		return code.ACCOUNT_DOES_NOT_EXIST, []byte("SOURCE")
	}

	sourceBalance := binary.BigEndian.Uint64(sourceBalanceB)
	if sourceBalance < amount { // + some gas?
		return code.INSUFFICIENT_BALANCE, nil
	}

	// holding account is a special case - it's not an EC point but just a string which is uncompressable
	if bytes.Compare(outAddr, holdingAccountAddress) != 0 {
		if err := outAddr.Compress(); err != nil {
			// 'normal' address is invalid
			return code.MALFORMED_ADDRESS, []byte("TARGET")
		}
	}

	if _, retCodeT := app.queryBalance(outAddr); retCodeT != code.OK {
		return code.ACCOUNT_DOES_NOT_EXIST, []byte("TARGET")
	}

	return code.OK, nil
}

// the tx prefix was removed
func (app *NymApplication) checkNewAccountTx(tx []byte) uint32 {
	req := &transaction.NewAccountRequest{}
	var publicKey account.ECPublicKey

	if err := proto.Unmarshal(tx, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return code.INVALID_TX_PARAMS
	}

	if len(req.PublicKey) != account.PublicKeyUCSize && len(req.PublicKey) != account.PublicKeySize {
		return code.INVALID_TX_PARAMS
	}

	if !app.verifyCredential(req.Credential) {
		app.log.Info("Failed to verify IP credential")
		return code.INVALID_CREDENTIAL
	}

	publicKey = req.PublicKey

	msg := make([]byte, len(req.PublicKey)+len(req.Credential))
	copy(msg, req.PublicKey)
	copy(msg[len(req.PublicKey):], req.Credential)

	if !publicKey.VerifyBytes(msg, req.Sig) {
		app.log.Info("Failed to verify signature on request")
		return code.INVALID_SIGNATURE
	}

	return code.OK
}

func (app *NymApplication) checkTransferBetweenAccountsTx(tx []byte) uint32 {
	req := &transaction.AccountTransferRequest{}
	var sourcePublicKey account.ECPublicKey
	var targetPublicKey account.ECPublicKey

	if err := proto.Unmarshal(tx, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return code.INVALID_TX_PARAMS
	}

	sourcePublicKey = req.SourcePublicKey
	targetPublicKey = req.TargetPublicKey
	amountB := make([]byte, 8)
	binary.BigEndian.PutUint64(amountB, req.Amount)

	msg := make([]byte, len(sourcePublicKey)+len(targetPublicKey)+8)
	copy(msg, sourcePublicKey)
	copy(msg[len(sourcePublicKey):], targetPublicKey)
	copy(msg[len(sourcePublicKey)+len(targetPublicKey):], amountB)

	if !sourcePublicKey.VerifyBytes(msg, req.Sig) {
		app.log.Info("Failed to verify signature on request")
		return code.INVALID_SIGNATURE
	}

	if retCode, _ := app.validateTransfer(sourcePublicKey, targetPublicKey, req.Amount); retCode != code.OK {
		return retCode
	}

	return code.OK
}
