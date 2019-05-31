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
	"github.com/tendermint/tendermint/abci/types"
)

func (app *NymApplication) checkAccountBalanceQuery(req types.RequestQuery) types.ResponseQuery {
	val, err := app.retrieveAccountBalance(req.Data)
	if err != nil {
		return types.ResponseQuery{Code: code.ACCOUNT_DOES_NOT_EXIST}
	}
	return types.ResponseQuery{Code: code.OK, Key: req.Data, Value: balanceToBytes(val)}
}

func (app *NymApplication) printVk(req types.RequestQuery) (types.ResponseQuery, error) {
	if !tmconst.DebugMode {
		app.log.Info("Trying to use printVk not in debug mode")
		return types.ResponseQuery{}, tmconst.ErrNotInDebug
	}
	avk, err := app.retrieveAggregateVerificationKey()
	if err != nil {
		return types.ResponseQuery{Code: code.UNKNOWN}, err
	}
	fmt.Println(avk)
	return types.ResponseQuery{Code: code.OK}, nil
}
