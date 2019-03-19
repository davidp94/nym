// token.go - Nym token definition
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

// Package token defines Nym token structure and associated methods.
package token

import (
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// For future reference:
// tags can be accessed via reflections;
// t := reflect.TypeOf(T{})
// f, _ := t.FieldByName("f")
// f.Tag

var (
	allowedValues = []int{1, 2, 5, 10, 20, 50, 100}
)

type Token struct {
	privateKey  PrivateKey `coconut:"private"`
	sequenceNum *Curve.BIG `coconut:"private"`
	value       int32      `coconut:"public"` // should be limited to set of possible values to prevent traffic analysis
	// ttl         time.Time  `coconut:"public"`
}

func (t *Token) PrivateKey() PrivateKey {
	return t.privateKey
}

func (t *Token) SequenceNum() *Curve.BIG {
	return t.sequenceNum
}

func (t *Token) Value() int32 {
	return t.value
}

func (t *Token) GetPublicAndPrivateSlices() ([]*Curve.BIG, []*Curve.BIG) {
	// first private attribute has to be the sequence number
	// and the first public attribute should be the value
	pubM := make([]*Curve.BIG, 1)
	privM := make([]*Curve.BIG, 2)

	valBig := Curve.NewBIGint(int(t.value))
	// for any additional public attributes (that are not ints), just hash them into BIG:
	// attrBig := utils.HashBytesToBig(amcl.SHA256, attr)

	privM[0] = t.sequenceNum
	privM[1] = t.privateKey

	pubM[0] = valBig
	return pubM, privM
}

// should be associated with given client/user rather than token if I understand it correctly
type PrivateKey *Curve.BIG

type Credential *coconut.Signature

func (t *Token) PrepareBlindSign(params *coconut.Params, egPub *elgamal.PublicKey) (*coconut.Lambda, error) {
	pubM, privM := t.GetPublicAndPrivateSlices()
	return coconut.PrepareBlindSign(params, egPub, pubM, privM)
}

// temp, havent decided on where attrs will be generated, but want token instance for test
func New(s, k *Curve.BIG, val int32) *Token {
	return &Token{
		privateKey:  k,
		sequenceNum: s,
		value:       val,
	}
}
