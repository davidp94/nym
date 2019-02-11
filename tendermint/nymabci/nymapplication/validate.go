// validate.go - transaction validation logic.
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
	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
)

// checks if tx has expected length
func (app *NymApplication) validateTxLength(tx []byte) uint32 {
	txType := tx[0]
	switch txType {
	case transaction.TxTypeLookUpZeta:
		if len(tx) == constants.ECPLen+1 {
			return code.OK
		}
		return code.INVALID_TX_LENGTH
	default:
		// we can't compare the tx length with the expected one - we don't know what the correct one is supposed to be
		// TODO: contradicts the rule of failsafe defaults?
		return code.OK
	}
}

// validates tx against set of checks
func (app *NymApplication) validateTx(tx []byte) uint32 {
	// TODO: more validations
	return app.validateTxLength(tx)
}
