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
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

func prefixKey(prefix []byte, key []byte) []byte {
	b := make([]byte, len(key)+len(prefix))
	copy(b, prefix)
	copy(b[len(prefix):], key)

	return b
}

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

func (app *NymApplication) getSimpleCoconutParams() *coconut.Params {
	p := Curve.NewBIGints(Curve.CURVE_Order)
	g1 := Curve.ECP_generator()
	g2 := Curve.ECP2_generator()
	_, hsb := app.state.db.Get(coconutHs)
	hs := coconut.CompressedBytesToECPSlice(hsb)

	return coconut.NewParams(nil, p, g1, g2, hs)
}

func (app *NymApplication) createNewAccountOp(publicKey account.ECPublicKey) bool {
	if err := publicKey.Compress(); err != nil {
		app.log.Error("All checks were successful, but failed to compress the key. UNDEFINED BEHAVIOUR")
		return false
	}

	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, startingBalance)

	dbEntry := prefixKey(accountsPrefix, publicKey)
	app.state.db.Set(dbEntry, value)

	hexname := base64.StdEncoding.EncodeToString(publicKey)
	app.log.Info(fmt.Sprintf("Created new account: %v with starting balance: %v", hexname, startingBalance))
	return true
}

// returns if operation was successful
// todo: change return to include ret code
func (app *NymApplication) transferFundsOp(inAddr, outAddr account.ECPublicKey, amount uint64) bool {
	// holding account is a special case - it's not an EC point but just a string which is uncompressable
	if bytes.Compare(inAddr, holdingAccountAddress) != 0 {
		if err := inAddr.Compress(); err != nil {
			// 'normal' address is invalid
			return false
		}
	}
	sourceBalanceB, retCode := app.queryBalance(inAddr)
	if retCode != code.OK {
		return false // among other things checks if the source account exists
	}

	sourceBalance := binary.BigEndian.Uint64(sourceBalanceB)
	if sourceBalance < amount { // + some gas?
		return false
	}

	if err := outAddr.Compress(); err != nil {
		return false
	}
	targetBalanceB, retCodeT := app.queryBalance(outAddr)
	if retCodeT != code.OK {
		return false // among other things checks if the source account exists
	}

	targetBalance := binary.BigEndian.Uint64(targetBalanceB)

	// finally initiate the transfer
	sourceResult := sourceBalance - amount
	targetResult := targetBalance + amount

	sourceResultB := make([]byte, 8)
	targetResultB := make([]byte, 8)

	binary.BigEndian.PutUint64(sourceResultB, sourceResult)
	binary.BigEndian.PutUint64(targetResultB, targetResult)

	sourceDbEntry := prefixKey(accountsPrefix, inAddr)
	app.state.db.Set(sourceDbEntry, sourceResultB)

	targetDbEntry := prefixKey(accountsPrefix, outAddr)
	app.state.db.Set(targetDbEntry, targetResultB)

	app.log.Info(fmt.Sprintf("Transferred %v from %v to %v",
		amount, base64.StdEncoding.EncodeToString(inAddr), base64.StdEncoding.EncodeToString(outAddr)))

	return true
}
