// constants.go - Set of constants.
// Copyright (C) 2018  Jedrzej Stuczynski.
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

import (
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const (
	// NumberOfEntropyBytes defines number of bytes of entropy used to seed RNG.
	NumberOfEntropyBytes = 256

	// MB represents number of bytes each BIG takes.
	MB = int(Curve.MODBYTES)

	// BIGLen is alias for MB.
	BIGLen = MB

	// ECPLen represents number of bytes each ECP takes.
	ECPLen = MB + 1

	// ECPLenUC represents number of bytes each ECP takes in uncompressed form.
	ECPLenUC = 2*MB + 1

	// ECP2Len represents number of bytes each ECP2 takes.
	ECP2Len = 4 * MB

	// SecretKeyType defines PEM Type for Coconut Secret Key.
	SecretKeyType = "COCONUT SECRET KEY"

	// VerificationKeyType defines PEM Type for Coconut Verification Key.
	VerificationKeyType = "COCONUT VERIFICATION KEY"

	// ElGamalPublicKeyType defines PEM Type for Coconut-specific ElGamal Public Key.
	ElGamalPublicKeyType = "COCONUT-ELGAMAL PUBLIC KEY"

	// ElGamalPrivateKeyType defines PEM Type for Coconut-specific ElGamal Private Key.
	ElGamalPrivateKeyType = "COCONUT-ELGAMAL PRIVATE KEY"
)
