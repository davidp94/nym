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
	"errors"

	"github.com/milagro-crypto/amcl/version3/go/amcl"
	Curve "github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

// hashBytes takes a bytes message and returns its SHA256/SHA384/SHA512 hash
// It is based on the amcl implementation: https://github.com/milagro-crypto/amcl/blob/master/version3/go/MPIN.go#L83
func hashBytes(sha int, b []byte) ([]byte, error) {
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

	const RM int = int(Curve.MODBYTES)
	var W [RM]byte
	if sha >= RM {
		for i := 0; i < RM; i++ {
			W[i] = R[i]
		}
	} else {
		for i := 0; i < sha; i++ {
			W[i+RM-sha] = R[i]
		}
		for i := 0; i < RM-sha; i++ {
			W[i] = 0
		}
	}
	return W[:], nil
}

// HashStringToBig takes a string message and maps it to a BIG number
func HashStringToBig(sha int, m string) (*Curve.BIG, error) {
	b := []byte(m)
	return HashBytesToBig(sha, b)
}

// HashBytesToBig takes a bytes message and maps it to a BIG number
// It is based on the amcl implementation: https://github.com/milagro-crypto/amcl/blob/master/version3/go/MPIN.go#L707
func HashBytesToBig(sha int, b []byte) (*Curve.BIG, error) {
	hash, err := hashBytes(sha, b)
	y := Curve.FromBytes(hash)
	q := Curve.NewBIGints(Curve.CURVE_Order)
	y.Mod(q)
	if err != nil {
		return nil, err
	}
	return y, nil
}

// HashStringToG1 takes a string message and maps it to a point on G1 Curve
func HashStringToG1(sha int, m string) (*Curve.ECP, error) {
	b := []byte(m)
	return HashBytesToG1(sha, b)
}

// HashBytesToG1 takes a bytes message and maps it to a point on G1 Curve
func HashBytesToG1(sha int, b []byte) (*Curve.ECP, error) {
	hash, err := hashBytes(sha, b)
	if err != nil {
		return nil, err
	}
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
