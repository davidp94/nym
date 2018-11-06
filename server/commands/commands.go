// todo: move to separate repo together with server dir?

// commands.go - commands for coconut server
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

// Package commands define command types used by coconut server.
package commands

import (
	"github.com/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// todo: add length to EVERY packet sent, even if it can be easily implied

const (
	GetVerificationKeyID CommandID = 100
	SignID               CommandID = 101
	VerifyID             CommandID = 102
)

type Command interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(data []byte) error
}

type CommandID byte

type RawCommand struct {
	id      CommandID
	payload []byte
}

func NewRawCommand(id CommandID, payload []byte) *RawCommand {
	return &RawCommand{id, payload}
}

func (c *RawCommand) Id() CommandID {
	return c.id
}

func (c *RawCommand) Payload() []byte {
	return c.payload
}

func (c *RawCommand) ToBytes() []byte {
	b := make([]byte, 1+len(c.payload))
	b[0] = byte(c.id)
	copy(b[1:], c.payload)
	return b
}

func FromBytes(b []byte) Command {
	id := CommandID(b[0])
	payload := b[1:]
	var cmd Command
	var err error
	switch id {
	case GetVerificationKeyID:
		vkCmd := &Vk{}
		err = vkCmd.UnmarshalBinary(payload) // in case implementation changes
		cmd = vkCmd
	case SignID:
		signCmd := &Sign{}
		err = signCmd.UnmarshalBinary(payload)
		cmd = signCmd
	case VerifyID:
		verifyCmd := &Verify{}
		err = verifyCmd.UnmarshalBinary(payload)
		cmd = verifyCmd
	}
	if err != nil {
		return nil
	}
	return cmd
}

type CommandRequest struct {
	cmd   Command
	retCh chan interface{}
}

func NewCommandRequest(cmd Command, ch chan interface{}) *CommandRequest {
	return &CommandRequest{cmd: cmd, retCh: ch}
}

func (cr *CommandRequest) RetCh() chan interface{} {
	return cr.retCh
}

func (cr *CommandRequest) Cmd() Command {
	return cr.cmd
}

// all the below commands are recovered from payload field in Command
// id is used to determine which one to recover

type Sign struct {
	pubM []*Curve.BIG
}

func (s *Sign) PubM() []*Curve.BIG {
	return s.pubM
}

func NewSign(pubM []*Curve.BIG) *Sign {
	return &Sign{pubM}
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (s *Sign) UnmarshalBinary(data []byte) error {
	blen := constants.BIGLen

	if len(data)%blen != 0 {
		// this really, really, really needs to be moved to other package
		return constants.ErrUnmarshalLength
	}

	n := len(data) / blen
	pubM := make([]*Curve.BIG, n)
	for i := range pubM {
		pubM[i] = Curve.FromBytes(data[i*blen:])
	}
	s.pubM = pubM
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (s *Sign) MarshalBinary() ([]byte, error) {
	blen := constants.BIGLen

	data := make([]byte, blen*len(s.pubM))
	for i := range s.pubM {
		s.pubM[i].ToBytes(data[i*blen:])
	}
	return data, nil
}

// not sure if will end up being used as keys might be shared in a different way
type Vk struct{}

func (v *Vk) UnmarshalBinary(data []byte) error { return nil }
func (v *Vk) MarshalBinary() ([]byte, error)    { return make([]byte, 0), nil }

type Verify struct {
	sig  *coconut.Signature
	pubM []*Curve.BIG
}

func (v *Verify) Sig() *coconut.Signature {
	return v.sig
}

func (v *Verify) PubM() []*Curve.BIG {
	return v.pubM
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (v *Verify) UnmarshalBinary(data []byte) error {
	blen := constants.BIGLen
	eclen := constants.ECPLen

	if (len(data)-2*eclen)%blen != 0 {
		return constants.ErrUnmarshalLength
	}

	sig := &coconut.Signature{}
	err := sig.UnmarshalBinary(data[:2*eclen])
	if err != nil {
		return err
	}
	n := (len(data) - 2*eclen) / blen
	pubM := make([]*Curve.BIG, n)
	for i := range pubM {
		pubM[i] = Curve.FromBytes(data[2*eclen+i*blen:])
	}
	v.sig = sig
	v.pubM = pubM
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (v *Verify) MarshalBinary() ([]byte, error) {
	blen := constants.BIGLen
	eclen := constants.ECPLen

	data := make([]byte, 2*eclen+blen*len(v.pubM))
	sigB, err := v.sig.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data, sigB)
	for i := range v.pubM {
		v.pubM[i].ToBytes(data[2*eclen+i*blen:])
	}
	return data, nil
}

func NewVerify(pubM []*Curve.BIG, sig *coconut.Signature) *Verify {
	return &Verify{
		pubM: pubM,
		sig:  sig,
	}
}
