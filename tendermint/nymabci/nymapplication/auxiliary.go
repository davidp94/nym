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
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"

	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	ethcommon "github.com/ethereum/go-ethereum/common"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

func balanceToBytes(balance uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, balance)
	return b
}

func prefixKey(prefix []byte, key []byte) []byte {
	b := make([]byte, len(key)+len(prefix))
	copy(b, prefix)
	copy(b[len(prefix):], key)

	return b
}

// randomInt returns a random int, s.t.  s.t. 0 < n < max and was not generated before. It uses the provided rng
// to eliminate sources of non-determinism
func randomInt(seen map[int]struct{}, max int, rand *rand.Rand) int {
	if len(seen) >= max-1 {
		return -1
	}
	candidate := 1 + rand.Intn(max-1)
	if _, ok := seen[candidate]; ok {
		return randomInt(seen, max, rand)
	}
	return candidate
}

// randomInts returns random (non-repetitive) q ints, s.t. 0 < n < max
// It initialises everything with the provided source to remove all possible sources of non-determinism
func randomInts(q int, max int, source rand.Source) ([]int, error) {
	if q >= max || q <= 0 {
		return nil, errors.New("can't generate enough random numbers")
	}
	if source == nil {
		return nil, errors.New("nil rng source provided")
	}
	rand := rand.New(source)

	ints := make([]int, q)
	seen := make(map[int]struct{})
	for i := range ints {
		r := randomInt(seen, max, rand)
		// theoretically should never be thrown due to initial check
		if r == -1 {
			return nil, errors.New("could not generate enough random numbers")
		}
		ints[i] = r
		seen[r] = struct{}{}
	}
	return ints, nil
}

// checks if account with given address exists in the database
func (app *NymApplication) checkIfAccountExists(address []byte) bool {
	_, err := app.retrieveAccountBalance(address)
	return err != nil
}

// getSimpleCoconutParams returns params required to perform coconut operations, however, they do not include
// the bpgroup that is required for generating random numbers. However, this is not required by the abci.
func (app *NymApplication) getSimpleCoconutParams() *coconut.Params {
	p := Curve.NewBIGints(Curve.CURVE_Order)
	g1 := Curve.ECP_generator()
	g2 := Curve.ECP2_generator()
	hs, err := app.retrieveHs()
	if err != nil {
		return nil
	}

	return coconut.NewParams(nil, p, g1, g2, hs)
}

// returns bool to indicate if the operation was successful
func (app *NymApplication) createNewAccountOp(address ethcommon.Address) bool {
	if startingBalance != 0 && !tmconst.DebugMode {
		app.log.Error("Trying to set starting balance different than 0 while the app is not in debug mode")
		return false
	}
	app.setAccountBalance(address[:], startingBalance)

	app.log.Info(fmt.Sprintf("Created new account: %v with starting balance: %v", address.Hex(), startingBalance))
	return true
}

func (app *NymApplication) increaseBalanceBy(address []byte, value uint64) error {
	currentBalance, err := app.retrieveAccountBalance(address)
	if err != nil {
		return err
	}
	app.log.Debug(fmt.Sprintf("Increasing balance of %v by %v (from %v to %v)",
		ethcommon.BytesToAddress(address).Hex(),
		value,
		currentBalance,
		currentBalance+value,
	))
	app.setAccountBalance(address, currentBalance+value)
	return nil
}

func (app *NymApplication) decreaseBalanceBy(address []byte, value uint64) error {
	currentBalance, err := app.retrieveAccountBalance(address)
	if err != nil {
		return err
	}
	app.log.Debug(fmt.Sprintf("Decreasing balance of %v by %v (from %v to %v)",
		ethcommon.BytesToAddress(address).Hex(),
		value,
		currentBalance,
		currentBalance-value,
	))
	app.setAccountBalance(address, currentBalance-value)
	return nil
}

// returns code to indicate if the operation was successful and, if applicable, how it failed
// Simple bool would not provide enough information
// also returns any additional data
// TODO: also limit transaction value to signed int32?
func (app *NymApplication) transferFundsOp(inAddr, outAddr []byte, amount uint64) (uint32, []byte) {
	if retCode, data := app.validateTransfer(inAddr, outAddr, amount); retCode != code.OK {
		return retCode, data
	}

	if err := app.decreaseBalanceBy(inAddr, amount); err != nil {
		// this is undefined behaviour as account was already checked in validate transfer
		// so something malicious must have happened
		panic(err)
	}
	if err := app.increaseBalanceBy(outAddr, amount); err != nil {
		// this is undefined behaviour as account was already checked in validate transfer
		// so something malicious must have happened
		panic(err)
	}

	app.log.Info(fmt.Sprintf("Transferred %v from %v to %v",
		amount, ethcommon.BytesToAddress(inAddr).Hex(), ethcommon.BytesToAddress(outAddr).Hex()))

	return code.OK, nil
}
