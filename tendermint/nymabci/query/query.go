// query.go - query logic
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

// Package query defines query logic for the Nym application.
package query

// todo: restructure somehow to not have 2 query.go files

import (
	"0xacab.org/jstuczyn/CoconutGo/constants"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const (
	QueryCheckBalancePath string = "/balance"
)

var (
	_ = constants.ECP2Len
	_ = Curve.MODBITS
)
