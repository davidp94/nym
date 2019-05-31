// packet_test.go - tests for the packet package
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
package packet

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshal(t *testing.T) {
	lengths := []int{0, 1, 16, 32, 512, 1024, 1000000}
	for _, l := range lengths {
		payload := make([]byte, l)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("Failed to read random bytes: %v", err)
		}
		p := NewPacket(payload)
		b, err := p.MarshalBinary()
		assert.Nil(t, err)

		pbin, err := FromBytes(b)
		assert.Nil(t, err)
		punm := &Packet{}
		assert.Nil(t, punm.UnmarshalBinary(b))

		assert.Equal(t, p, pbin)
		assert.Equal(t, p, punm)
	}
}

func TestNewPacket(t *testing.T) {
	lengths := []int{0, 1, 16, 32, 512, 1024, 1000000}
	for _, l := range lengths {
		payload := make([]byte, l)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("Failed to read random bytes: %v", err)
		}
		p := NewPacket(payload)
		assert.NotNil(t, p)
		assert.Len(t, p.payload, l)
		assert.True(t, uint32(len(p.payload)+headerLength) == p.header.packetLength)
	}
}
