// auxiliary.go - Set of auxiliary methods used by Tenderming ABCI for Nym
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
)

// checks if account with given address exists in the database
func (app *NymApplication) checkIfAccountExists(address []byte) bool {
	if !account.ValidateAddress(address) {
		return false
	}
	key := prefixKey(accountsPrefix, address)

	_, val := app.state.db.Get(key)
	if val != nil {
		return true
	}
	return false
}
