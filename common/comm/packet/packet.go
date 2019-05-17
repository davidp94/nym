// packet.go - encapsulation of network data
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

// Package packet defines packet structure that is sent on the wire between multiple entities
package packet

import (
	"encoding/binary"
	"errors"
)

const (
	headerLength = 4 // just holds length of payload - 4 bytes
)

type header struct {
	// currently only length but gives option to expand in future
	packetLength uint32
}

// Packet encapsulates a packet sent over the wire that contains some payload and a header
type Packet struct {
	header  *header
	payload []byte
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (h *header) UnmarshalBinary(data []byte) error {
	if len(data) != headerLength {
		return errors.New("the byte array provided is incomplete")
	}
	h.packetLength = binary.BigEndian.Uint32(data)
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (h *header) MarshalBinary() ([]byte, error) {
	b := make([]byte, headerLength)
	binary.BigEndian.PutUint32(b, h.packetLength) // it is crucial that length is the first encoded attribute
	return b, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (p *Packet) UnmarshalBinary(data []byte) error {
	header := &header{}
	if err := header.UnmarshalBinary(data[:headerLength]); err != nil {
		return err
	}
	payload := data[headerLength:]
	p.header = header
	p.payload = payload
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (p *Packet) MarshalBinary() ([]byte, error) {
	b := make([]byte, p.header.packetLength)
	hdr, err := p.header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(b, hdr)
	copy(b[headerLength:], p.payload)
	return b, nil
}

// Payload returns Payload part of the Packet.
func (p *Packet) Payload() []byte {
	return p.payload
}

// FromBytes parses byte stream and returns a corresponding packet.
func FromBytes(data []byte) (*Packet, error) {
	packet := &Packet{}
	err := packet.UnmarshalBinary(data)
	return packet, err
}

// NewPacket returns new instance of packet with provided payload
func NewPacket(payload []byte) *Packet {
	header := &header{
		packetLength: uint32(len(payload)) + headerLength,
	}
	return &Packet{
		header:  header,
		payload: payload,
	}
}
