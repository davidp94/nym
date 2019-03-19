// auxiliary.go - set of auxiliary functions for the Coconut scheme.
// Copyright (C) 2018-2019  Jedrzej Stuczynski.
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

// Package coconut provides the functionalities required by the Coconut Scheme.
package coconut

import (
	"errors"
	"strings"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// ValidateKeyPair checks if the coconut keypair was correctly formed.
func ValidateKeyPair(sk *SecretKey, vk *VerificationKey) bool {
	if len(sk.y) != len(vk.beta) || !sk.Validate() || !vk.Validate() {
		return false
	}
	if !vk.alpha.Equals(Curve.G2mul(vk.g2, sk.x)) {
		return false
	}
	for i := range sk.y {
		if !vk.beta[i].Equals(Curve.G2mul(vk.g2, sk.y[i])) {
			return false
		}
	}
	return true
}

// getBaseFromAttributes generates the base h from public attributes.
// It is only used for Sign function that works exlusively on public attributes
func getBaseFromAttributes(pubM []*Curve.BIG) (*Curve.ECP, error) {
	s := make([]string, len(pubM))
	for i := range pubM {
		s[i] = utils.ToCoconutString(pubM[i])
	}
	return utils.HashStringToG1(amcl.SHA512, strings.Join(s, ","))
}

// GetRandomNums generates n random numbers.
func GetRandomNums(params *Params, n int) []*Curve.BIG {
	p, rng := params.p, params.G.Rng()
	r := make([]*Curve.BIG, n)
	for i := range r {
		r[i] = Curve.Randomnum(p, rng)
	}
	return r
}

// BigSliceFromByteSlices recovers a slice of BIG nums from a slice of slices of bytes.
func BigSliceFromByteSlices(b [][]byte) []*Curve.BIG {
	bigs := make([]*Curve.BIG, len(b))
	for i := range b {
		bigs[i] = Curve.FromBytes(b[i])
	}
	return bigs
}

// BigSliceToByteSlices converts a slice of BIG nums to slice of slices of bytes.
func BigSliceToByteSlices(s []*Curve.BIG) ([][]byte, error) {
	// need to allow encoding empty (not nil) slices for blindsign of 0 public attrs
	if s == nil {
		return nil, errors.New("invalid BIG slice provided")
	}
	blen := constants.BIGLen
	b := make([][]byte, len(s))
	for i := range b {
		if s[i] == nil {
			return nil, errors.New("nil element in slice present")
		}
		b[i] = make([]byte, blen)
		s[i].ToBytes(b[i])
	}
	return b, nil
}

// ValidateBigSlice checks if the slice of BIG nums contain no nil elements.
func ValidateBigSlice(s []*Curve.BIG) bool {
	if s == nil {
		return false
	}
	for i := range s {
		if s[i] == nil {
			return false
		}
	}
	return true
}

// ECPSliceToCompressedBytes takes slice of EC points and returns their combined compressed bytes representation.
func ECPSliceToCompressedBytes(s []*Curve.ECP) []byte {
	b := make([]byte, len(s)*constants.ECPLen)
	for i := range s {
		s[i].ToBytes(b[constants.ECPLen*i:], true)
	}
	return b
}

// CompressedBytesToECPSlice takes bytes of combined bytes representation of compressed EC points
// and returns their proper objects.
func CompressedBytesToECPSlice(b []byte) []*Curve.ECP {
	s := make([]*Curve.ECP, len(b)/constants.ECPLen)
	for i := 0; i < len(s); i++ {
		s[i] = Curve.ECP_fromBytes(b[i*constants.ECPLen : (i+1)*constants.ECPLen])
	}
	return s
}
