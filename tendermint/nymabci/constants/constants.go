// constants.go - Set of constants related to the blockchain application.
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

// Package constants declares system-wide constants.
package constants

// nolint: gochecknoglobals
var (
	// SpentZetaPrefix represents prefix for each zeta in the database to indicate it has been spent.
	SpentZetaPrefix = []byte("SPENT")

	// HoldingAccountAddress represents the account address used by the 'Holding Account'.
	HoldingAccountAddress = []byte("HOLDING ACCOUNT")

	// AggregateVkKey represents the database entry for the aggregate verification key of the threshold number
	// of issuing authorities of the system. It is used for credential verification.
	AggregateVkKey = []byte("avk")

	// IaKeyPrefix represents the prefix for particular issuing authority to store their keys.
	IaKeyPrefix = []byte("IssuingAuthority")

	// CommitmentsPrefix (TO BE REMOVED) represents prefix for each commitment in the database to indicate
	// it was already sent and hence funds were moved
	CommitmentsPrefix = []byte("commitment")

	// AccountsPrefix represents prefix for each account in the database to indicate amount of associated tokens.
	AccountsPrefix = []byte("account")

	// CoconutHsKey represents the database entry for the EC points of G1 as defined by
	// the public, system-wide coconut parameters.
	CoconutHsKey = []byte("coconutHs")

	// SeenNoncePrefix represents prefix for each seen nonce in the database.
	SeenNoncePrefix = []byte("NONCE")

	// CredentialRequestKeyPrefix represents prefix attached to key field of kvpair in the tags of response
	// to a successful request to transfer tokents to a holding account.
	CredentialRequestKeyPrefix = []byte("GETCREDENTIAL")
)
