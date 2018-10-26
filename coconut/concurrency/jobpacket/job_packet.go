// job_packet.go - Job packets for the Coconut scheme.
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

// Package jobpacket provides allows implementing simple job queue.
package jobpacket

import (
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// JobPacket encapsulates the data required to perform given action concurrently,
// i.e. the actual operation and a channel to write the result to.
type JobPacket struct {
	OutCh chan<- interface{}
	Op    func() (interface{}, error)
}

// MakeG1MulPacket combines MakeG1MulOp and New into a single function for increased code readibility.
func MakeG1MulPacket(outCh chan<- interface{}, g1 *Curve.ECP, x *Curve.BIG) *JobPacket {
	op := func() (interface{}, error) {
		return Curve.G1mul(g1, x), nil
	}
	return New(outCh, op)
}

// MakeG2MulPacket combines MakeG2MulOp and New into a single function for increased code readibility.
func MakeG2MulPacket(outCh chan<- interface{}, g2 *Curve.ECP2, x *Curve.BIG) *JobPacket {
	op := func() (interface{}, error) {
		return Curve.G2mul(g2, x), nil
	}
	return New(outCh, op)
}

// MakePairingPacket combines MakePairingOp and New into a single function for increased code readibility.
func MakePairingPacket(outCh chan<- interface{}, g1 *Curve.ECP, g2 *Curve.ECP2) *JobPacket {
	op := func() (interface{}, error) {
		return Curve.Fexp(Curve.Ate(g2, g1)), nil
	}
	return New(outCh, op)
}

// New creates a new job packet to be written into a job queue.
func New(outCh chan<- interface{}, op func() (interface{}, error)) *JobPacket {
	return &JobPacket{
		OutCh: outCh,
		Op:    op,
	}
}
