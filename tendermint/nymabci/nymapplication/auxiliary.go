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
	"errors"
	"fmt"
	"math/rand"

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
		return nil, errors.New("Can't generate enough random numbers")
	}
	if source == nil {
		return nil, errors.New("Nil rng source provided")
	}
	rand := rand.New(source)

	ints := make([]int, q)
	seen := make(map[int]struct{})
	for i := range ints {
		r := randomInt(seen, max, rand)
		// theoretically should never be thrown due to initial check
		if r == -1 {
			return nil, errors.New("Could not generate enough random numbers")
		}
		ints[i] = r
		seen[r] = struct{}{}
	}
	return ints, nil
}

// checks if account with given address exists in the database
// it WILL NOT try to compress address (even if possible) in case there was ever need to store uncompressed addresses
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

// getSimpleCoconutParams returns params required to perform coconut operations, however, they do not include
// the bpgroup that is required for generating random numbers. However, this is not required by the abci.
func (app *NymApplication) getSimpleCoconutParams() *coconut.Params {
	p := Curve.NewBIGints(Curve.CURVE_Order)
	g1 := Curve.ECP_generator()
	g2 := Curve.ECP2_generator()
	_, hsb := app.state.db.Get(coconutHs)
	hs := coconut.CompressedBytesToECPSlice(hsb)

	return coconut.NewParams(nil, p, g1, g2, hs)
}

// returns bool to indicate if the operation was successful
func (app *NymApplication) createNewAccountOp(publicKey account.ECPublicKey) bool {
	// Compress also performs basic validation
	if err := publicKey.Compress(); err != nil {
		return false
	}

	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, startingBalance)

	dbEntry := prefixKey(accountsPrefix, publicKey)
	app.state.db.Set(dbEntry, value)

	b64name := base64.StdEncoding.EncodeToString(publicKey)
	app.log.Info(fmt.Sprintf("Created new account: %v with starting balance: %v", b64name, startingBalance))
	return true
}

// returns code to indicate if the operation was successful and, if applicable, how it failed
// Simple bool would not provide enough information
// also returns any additional data
// TODO: also limit transaction value to signed int32?
func (app *NymApplication) transferFundsOp(inAddr, outAddr account.ECPublicKey, amount uint64) (uint32, []byte) {
	if retCode, data := app.validateTransfer(inAddr, outAddr, amount); retCode != code.OK {
		return retCode, data
	}

	// nolint: gosec
	if bytes.Compare(inAddr, holdingAccountAddress) != 0 {
		inAddr.Compress()
	}

	// nolint: gosec
	if bytes.Compare(outAddr, holdingAccountAddress) != 0 {
		outAddr.Compress()
	}

	// we already know it will succeed
	sourceBalanceB, _ := app.queryBalance(inAddr)
	targetBalanceB, _ := app.queryBalance(outAddr)

	// TODO: replace it with some fancy byte operations to get rid of two conversions
	sourceBalance := binary.BigEndian.Uint64(sourceBalanceB)
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

	return code.OK, nil
}
