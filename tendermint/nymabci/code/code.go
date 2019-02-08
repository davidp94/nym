// code.go - Nym application return codes
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

// Package code defines return codes for the Nym application
package code

const (
	// as per spec, codes have to be represented as uint32 and 0 is reserved for OK
	OK                       uint32 = 0
	UNKNOWN                  uint32 = 1
	INVALID_TX_LENGTH        uint32 = 2
	INVALID_TX_PARAMS        uint32 = 3
	INVALID_QUERY_PARAMS     uint32 = 4
	ACCOUNT_DOES_NOT_EXIST   uint32 = 5
	INSUFFICIENT_BALANCE     uint32 = 6
	INVALID_CREDENTIAL       uint32 = 7
	INVALID_SIGNATURE        uint32 = 8
	INVALID_MERCHANT_ADDRESS uint32 = 9
	MERCHANT_DOES_NOT_EXIST  uint32 = 10
	COULD_NOT_TRANSFER       uint32 = 11
)
