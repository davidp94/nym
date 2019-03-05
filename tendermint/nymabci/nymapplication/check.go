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
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	proto "github.com/golang/protobuf/proto"
)

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
