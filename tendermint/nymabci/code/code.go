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

	// OK represents a success.
	OK uint32 = 0
	// UNKNOWN represents a failure due to unknown causes.
	UNKNOWN uint32 = 1
	// INVALID_TX_LENGTH represents error due to tx having unexpected length.
	INVALID_TX_LENGTH uint32 = 2
	// INVALID_TX_PARAMS represents error due to tx having incorrect attributes embedded.
	INVALID_TX_PARAMS uint32 = 3
	// INVALID_QUERY_PARAMS represents error due to query having incorrect attributes embedded.
	INVALID_QUERY_PARAMS uint32 = 4
	// ACCOUNT_DOES_NOT_EXIST represents error due to trying to interact with an account that does not exist.
	ACCOUNT_DOES_NOT_EXIST uint32 = 5
	// INSUFFICIENT_BALANCE represents error due to an account having insufficient funds for the desired operation.
	INSUFFICIENT_BALANCE uint32 = 6
	// INVALID_CREDENTIAL represents error due to failing to verify credential.
	INVALID_CREDENTIAL uint32 = 7
	// INVALID_SIGNATURE represents error due to failing to verify signature.
	INVALID_SIGNATURE uint32 = 8
	// INVALID_MERCHANT_ADDRESS represents error due to malformed merchant address.
	INVALID_MERCHANT_ADDRESS uint32 = 9
	// MERCHANT_DOES_NOT_EXIST represents error when trying to spend credential at non-existing merchant.
	// Only applicable if system is set to not create accounts for non-existent merchants.
	MERCHANT_DOES_NOT_EXIST uint32 = 10
	// COULD_NOT_TRANSFER represents a generic error for failing to transfer funds between accounts.
	COULD_NOT_TRANSFER uint32 = 11 // todo: replace occurences with more specific errors
)

// ToString returns string representation of the return code. It is useful for making human-readable responses.
func ToString(code uint32) string {
	switch code {
	case OK:
		return "OK"
	case UNKNOWN:
		return "Unknown"
	case INVALID_TX_LENGTH:
		return "Invalid Tx Length"
	case INVALID_TX_PARAMS:
		return "Invalid Tx Params"
	case INVALID_QUERY_PARAMS:
		return "Invalid Query Params"
	case ACCOUNT_DOES_NOT_EXIST:
		return "Account Does Not Exist"
	case INSUFFICIENT_BALANCE:
		return "Insufficient Balance"
	case INVALID_CREDENTIAL:
		return "Invalid Credential"
	case INVALID_SIGNATURE:
		return "Invalid Signature"
	case INVALID_MERCHANT_ADDRESS:
		return "Invalid Merchant Address"
	case MERCHANT_DOES_NOT_EXIST:
		return "Merchant Does Not Exist"
	case COULD_NOT_TRANSFER:
		return "Could Not Perform Transfer"
	default:
		return "Unknown Error Code"
	}
}
