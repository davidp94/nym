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
	"time"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
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
	value       int        `coconut:"public"` // should be limited to set of possible values to prevent traffic analysis
	ttl         time.Time  `coconut:public"`
}

// should be associated with given client/user rather than token
type PrivateKey *Curve.BIG

type Credential *coconut.Signature
