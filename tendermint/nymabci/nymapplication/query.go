// query.go - Query-related logic for Tendermint ABCI for Nym
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

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	ethcommon "github.com/ethereum/go-ethereum/common"
)

// returns balance represented uint64 as BiGEndian encoded byte array and the code
func (app *NymApplication) queryBalance(address []byte) ([]byte, uint32) {
	app.log.Debug(fmt.Sprintf("Checking balance for: %v", ethcommon.BytesToAddress(address).Hash()))
	key := prefixKey(tmconst.AccountsPrefix, address)

	_, val := app.state.db.Get(key)
	if val != nil {
		return val, code.OK
	}
	return nil, code.ACCOUNT_DOES_NOT_EXIST
}
