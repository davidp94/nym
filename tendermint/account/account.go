// account.go - Account definition
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

// Package account defines Nym account structure and associated methods.
// It uses a very similar structure to Tendermint Node IDs
package account

import (
	"errors"

	"0xacab.org/jstuczyn/CoconutGo/common/utils"
	"0xacab.org/jstuczyn/CoconutGo/constants"

	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// ECDSA_SHA defines sha algorithm used for signing messages.
const ECDSA_SHA = amcl.SHA256

// rng is used at both Keygen and Sign, however it is not appropriate to make it part of private key,
// making it global variable is also not the best solution but will remain so until better solution is found.
var rng *amcl.RAND

func init() {
	// todo: use go amino for marshaling?
	rng = amcl.NewRAND()
	raw, err := utils.GenerateRandomBytes(constants.NumberOfEntropyBytes)
	if err != nil {
		panic(err)
	}
	rng.Seed(constants.NumberOfEntropyBytes, raw)
}

const (
	// PublicKeyUCSize is the size, in bytes, of uncompressed public keys as used in this package.
	PublicKeyUCSize = constants.ECPLenUC
	// PublicKeySize is the size, in bytes, of compressed public keys as used in this package.
	PublicKeySize = constants.ECPLen
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = constants.BIGLen
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 2 * constants.BIGLen
)

// ECPrivateKey represents private key used for signing messages for authentication.
type ECPrivateKey []byte

// ECPublicKey represents public key used for verifying signed messages.
type ECPublicKey []byte

// Keygen calculates a public/private EC GF(p) key pair S,W where W=S.G mod EC(p),
// where S is the secret key and W is the public key and G is fixed generator.
// It is a wrapper for ECDH_KEY_PAIR_GENERATE by Milagro.
func Keygen() (ECPrivateKey, ECPublicKey) {
	S := make([]byte, PrivateKeySize)
	W := make([]byte, PublicKeyUCSize)

	Curve.ECDH_KEY_PAIR_GENERATE(rng, S, W)
	return S, W
}

// SignBytes produces IEEE ECDSA Signature.
// It is a wrapper for ECDH_ECPSP_DSA by Milagro.
func (pk ECPrivateKey) SignBytes(msg []byte) []byte {
	C, D := make([]byte, constants.BIGLen), make([]byte, constants.BIGLen)

	Curve.ECDH_ECPSP_DSA(ECDSA_SHA, rng, pk, msg, C, D)

	sig := make([]byte, SignatureSize)
	copy(sig[:], C[:])
	copy(sig[constants.BIGLen:], D[:])

	return sig
}

// VerifyBytes verifies IEEE ECDSA Signature.
// It is a wrapper for ECDH_ECPVP_DSA by Milagro.
func (pub ECPublicKey) VerifyBytes(msg []byte, sig []byte) bool {
	C, D := make([]byte, constants.BIGLen), make([]byte, constants.BIGLen)
	copy(C[:], sig[:constants.BIGLen])
	copy(D[:], sig[constants.BIGLen:])

	res := Curve.ECDH_ECPVP_DSA(ECDSA_SHA, pub, msg, C, D)
	return res == 0
}

// Compress compresses the byte array representing the public key.
func (pub *ECPublicKey) Compress() error {
	if len(*pub) == PublicKeySize {
		return errors.New("The key is already compressed")
	}
	b, err := utils.CompressECPBytes(*pub)
	if err != nil {
		return err
	}
	*pub = b
	return nil
}
