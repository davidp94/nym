// constants.go - ERC20-related constants
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

// package constants defines values associated with an ERC20 token
package constants

import "encoding/hex"

const (
	// function signatures (TODO: I ONLY MANUALLY VERIFIED TRANSFER; NEED TO MAKE SURE OTHERS MATCH UP)
	TotalSupplyMethodID  = "18160ddd" // totalSupply()
	BalanceOfMethodID    = "70a08231" // balanceOf(address)
	AllowanceMethodID    = "dd62ed3e" // allowance(address,address)
	TransferMethodID     = "a9059cbb" // transfer(address,uint256)
	ApproveMethodID      = "095ea7b3" // approve(address,uint256)
	TransferFromMethodID = "23b872dd" // transferFrom(address,address,uint256)
)

func MustMethodIDBytes(method string) []byte {
	bytes, err := hex.DecodeString(method)
	if err != nil {
		panic(err)
	}
	return bytes
}
