// utils.go - auxiliary functions
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

// Package utils provides auxiliary functions used throughout the repo
package utils

import (
	"crypto/rand"
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/constants"
)

// GenerateRandomBytes return slice of bytes of specified size of cryptographically secure random numbers.
// Refer to https://golang.org/pkg/crypto/rand/ for details regarding sources of entropy.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// CompressECPBytes takes the uncompressed byte representation of an EC point and
// returns corresponding compressed representation.
func CompressECPBytes(b []byte) ([]byte, error) {
	if len(b) != constants.ECPLenUC {
		return nil,
			fmt.Errorf("The uncompressed point has an invalid length of %v (expected %v)", len(b), constants.ECPLenUC)
	}
	if b[0] != 0x04 {
		return nil, fmt.Errorf("Unknown curve type prefix %v (expected 0x04)", b[0])
	}

	comp := make([]byte, constants.ECPLen)
	comp[0] = 2 + b[constants.ECPLenUC-1]&1
	copy(comp[1:], b[1:constants.BIGLen+1])

	return comp, nil
}
