// utils.go - set of auxiliary functions used by the Coconut scheme
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

// Package utils provides auxiliary functions required by the Coconut Scheme.
package utils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// todo: verify HashBytesToG1
// todo: wait for George's change in bplib for hashG1 -> worst case scenario is to try to butcher and modify amcl fork

// Printable is a wrapper for all objects that have ToString method. In particular Curve.ECP and Curve.ECP2.
type Printable interface {
	ToString() string
}

// ToCoconutString returns string representation of ECP or ECP2 object such that it is compatible with
// representation of Python implementation.
func ToCoconutString(p Printable) string {
	var b []byte
	switch v := p.(type) {
	case *Curve.ECP:
		b = make([]byte, constants.ECPLen)
		v.ToBytes(b, true)
	case *Curve.ECP2:
		b = make([]byte, constants.ECP2Len)
		v.ToBytes(b)
	case *Curve.BIG:
		// in this case it's simpler, but inconsistent as Python implementation returns capitalised hex for Bn
		str := v.ToString()
		return strings.ToUpper(str)
	}

	if len(b) > 0 {
		return hex.EncodeToString(b)

	}
	return ""
}

// addHashPadding ensures that resultant hash is long enough to be used in a FromBytes() method
func addHashPadding(sha int, b []byte) []byte {
	const RM int = int(Curve.MODBYTES)
	var W [RM]byte
	if sha >= RM {
		for i := 0; i < RM; i++ {
			W[i] = b[i]
		}
	} else {
		for i := 0; i < sha; i++ {
			W[i+RM-sha] = b[i]
		}
		for i := 0; i < RM-sha; i++ {
			W[i] = 0
		}
	}
	return W[:]
}

// HashBytes takes a bytes message and returns its SHA256/SHA384/SHA512 hash
// It is based on the amcl implementation: https://github.com/milagro-crypto/amcl/blob/master/version3/go/MPIN.go#L83
func HashBytes(sha int, b []byte) ([]byte, error) {
	var R []byte
	if sha == amcl.SHA256 {
		H := amcl.NewHASH256()
		H.Process_array(b)
		R = H.Hash()
	} else if sha == amcl.SHA384 {
		H := amcl.NewHASH384()
		H.Process_array(b)
		R = H.Hash()
	} else if sha == amcl.SHA512 {
		H := amcl.NewHASH512()
		H.Process_array(b)
		R = H.Hash()
	}

	if R == nil {
		return []byte{}, errors.New("Nil hash result")
	}
	return R, nil
}

// HashStringToBig takes a string message and maps it to a BIG number
func HashStringToBig(sha int, m string) (*Curve.BIG, error) {
	b := []byte(m)
	return HashBytesToBig(sha, b)
}

// HashBytesToBig takes a bytes message and maps it to a BIG number
// It is based on the amcl implementation: https://github.com/milagro-crypto/amcl/blob/master/version3/go/MPIN.go#L707
func HashBytesToBig(sha int, b []byte) (*Curve.BIG, error) {
	if Curve.CURVE_PAIRING_TYPE == Curve.BN && sha != amcl.SHA256 {
		// if curve used is BN254, ensure the used hash is SHA256 as this is what is used by Python implementation
		return nil, fmt.Errorf("Hashing to BIG on BN254 requires SHA256 (%d), but %d was used instead", amcl.SHA256, sha)
	}
	R, err := HashBytes(sha, b)
	if err != nil {
		return nil, err
	}
	hash := addHashPadding(sha, R)
	y := Curve.FromBytes(hash)
	// you should really take mod of this, however python coconut doesn't
	// what produces compatibility issues
	if Curve.CURVE_PAIRING_TYPE != Curve.BN {
		q := Curve.NewBIGints(Curve.CURVE_Order)
		y.Mod(q)
	}
	return y, nil
}

// HashStringToG1 takes a string message and maps it to a point on G1 Curve
func HashStringToG1(sha int, m string) (*Curve.ECP, error) {
	b := []byte(m)
	return HashBytesToG1(sha, b)
}

// HashBytesToG1 takes a bytes message and maps it to a point on G1 Curve
// Python implementation use SHA512, so temporarily hardcoding it here
// todo: NEED GEORGE'S FIX TO KNOW HOW TO FURTHER CHANGE IT
func HashBytesToG1(sha int, b []byte) (*Curve.ECP, error) {
	// Follow Python implementation
	if Curve.CURVE_PAIRING_TYPE == Curve.BN {
		// temp solution as it depends on George's decision in bplib
		if sha != amcl.SHA512 {
			return nil, fmt.Errorf("Hashing to G1 on BN254 requires SHA512 (%d), but %d was used instead", amcl.SHA512, sha)
		}

		p := Curve.NewBIGints(Curve.Modulus)
		E := Curve.NewECP() // new ECP object is at infinity
		hash := b
		var err error
		for E.Is_infinity() {
			hash, err = HashBytes(sha, hash)
			if err != nil {
				return nil, err
			}
			x := Curve.FromBytes(hash)
			x.Mod(p)
			E = Curve.NewECPbigint(x, 1)
		}
		return E, nil
	}
	hash, err := HashBytes(sha, b)
	if err != nil {
		return nil, err
	}
	hash = addHashPadding(sha, hash)
	// amcl have nice ECP_mapit function, but Python implementation differs,
	// however, if we are not using BN254 curve, I feel more confident using it instead,
	// considering they cover curve-specific edge cases which I am not aware of
	return Curve.ECP_mapit(hash), nil
}

// PolyEval evaluates a polynomial defined by the slice of coefficient coeff at point x.
// All operations are performed mod o.
// It's based on the original Python implementation:
// https://github.com/asonnino/coconut/blob/master/coconut/utils.py#L33.
func PolyEval(coeff []*Curve.BIG, x *Curve.BIG, o *Curve.BIG) *Curve.BIG {
	result := Curve.NewBIG()
	for i := range coeff {
		iBIG := Curve.NewBIGint(i)
		t := x.Powmod(iBIG, o)                             // x ^ i
		result = result.Plus(Curve.Modmul(coeff[i], t, o)) // coeff[0] * x ^ 0 + ... + coeff[i] * x ^ i
	}
	return result
}

// LagrangeBasis generates the lagrange basis polynomial li(x), for a polynomial of degree t-1.
// Takes x values from xs and calculates the basis for point xs[i]. It is done around at x (usually 0).
// It's based on the original Python implementation:
// https://github.com/asonnino/coconut/blob/master/coconut/utils.py#L37.
func LagrangeBasis(i int, o *Curve.BIG, xs []*Curve.BIG, x int) *Curve.BIG {
	numerator, denominator := Curve.NewBIGint(1), Curve.NewBIGint(1)
	xBIG := Curve.NewBIGint(x)
	for j, xVal := range xs {
		if j != i {
			t1 := xBIG.Minus(xVal)
			t1 = t1.Plus(o)
			t1.Mod(o)
			// numerator = ((x - xs[0]) % o) * ... * ((x - xs[j]) % o), j != i
			numerator = Curve.Modmul(numerator, t1, o)

			t2 := xs[i].Minus(xVal)
			t2 = t2.Plus(o)
			t2.Mod(o)
			// denominator = ((xs[i] - xs[0]) % o) * ... * ((xs[i] - xs[j]) % o), j != i
			denominator = Curve.Modmul(denominator, t2, o)
		}
	}
	denominator.Invmodp(o) // denominator = 1/denominator % o
	return Curve.Modmul(numerator, denominator, o)
}

// GenerateRandomBIGSlice creates a slice of specified length with random BIGs.
func GenerateRandomBIGSlice(p *Curve.BIG, rng *amcl.RAND, n int) []*Curve.BIG {
	s := make([]*Curve.BIG, n)
	for i := range s {
		s[i] = Curve.Randomnum(p, rng)
	}
	return s
}

// GenerateLagrangianCoefficients creates a slice of Lagragian Coefficients
func GenerateLagrangianCoefficients(n int, p *Curve.BIG, xs []*Curve.BIG, x int) []*Curve.BIG {
	l := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		l[i] = LagrangeBasis(i, p, xs, x)
	}
	return l
}
