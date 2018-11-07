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
	BlindSignID          CommandID = 103
	BlindVerifyID        CommandID = 104
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
	case BlindSignID:
		blindSignCmd := &BlindSign{}
		err = blindSignCmd.UnmarshalBinary(payload)
		cmd = blindSignCmd
	case BlindVerifyID:
		blindVerifyCmd := &BlindVerify{}
		err = blindVerifyCmd.UnmarshalBinary(payload)
		cmd = blindVerifyCmd
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

type BlindSign struct {
	blindSignMats *coconut.BlindSignMats
	gamma         *Curve.ECP
	pubM          []*Curve.BIG
	pubMLength    uint8 // 1 byte of overhead to significantly simplify marshaling/unmarshaling
}

func (bs *BlindSign) BlindSignMats() *coconut.BlindSignMats {
	return bs.blindSignMats
}

func (bs *BlindSign) Gamma() *Curve.ECP {
	return bs.gamma
}

func (bs *BlindSign) PubM() []*Curve.BIG {
	return bs.pubM
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (bs *BlindSign) UnmarshalBinary(data []byte) error {
	blen := constants.BIGLen
	eclen := constants.ECPLen

	pubMLength := data[0]
	pubM := make([]*Curve.BIG, pubMLength)
	for i := range pubM {
		pubM[i] = Curve.FromBytes(data[1+i*blen:])
	}
	gamma := Curve.ECP_fromBytes(data[1+len(pubM)*blen:])
	blindSignMats := &coconut.BlindSignMats{}
	err := blindSignMats.UnmarshalBinary(data[1+len(pubM)*blen+eclen:])
	if err != nil {
		return err
	}
	bs.blindSignMats = blindSignMats
	bs.gamma = gamma
	bs.pubM = pubM
	bs.pubMLength = pubMLength

	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (bs *BlindSign) MarshalBinary() ([]byte, error) {
	blen := constants.BIGLen
	eclen := constants.ECPLen

	// we don't care which method blindSignMats are using for marshaling
	bsmData, err := bs.blindSignMats.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, len(bsmData)+eclen+len(bs.pubM)*blen+1)
	data[0] = bs.pubMLength
	for i := range bs.pubM {
		bs.pubM[i].ToBytes(data[1+i*blen:])
	}
	bs.gamma.ToBytes(data[1+len(bs.pubM)*blen:], true)
	copy(data[1+len(bs.pubM)*blen+eclen:], bsmData)

	return data, nil
}

func NewBlindSign(blindSignMats *coconut.BlindSignMats, gamma *Curve.ECP, pubM []*Curve.BIG) *BlindSign {
	if len(pubM) > 255 {
		return nil
	}
	return &BlindSign{
		blindSignMats: blindSignMats,
		gamma:         gamma,
		pubM:          pubM,
		pubMLength:    uint8(len(pubM)),
	}
}

type BlindVerify struct {
	sig           *coconut.Signature
	blindShowMats *coconut.BlindShowMats
	pubM          []*Curve.BIG
	pubMLength    uint8 // 1 byte of overhead to significantly simplify marshaling/unmarshaling
}

func (bv *BlindVerify) BlindShowMats() *coconut.BlindShowMats {
	return bv.blindShowMats
}

func (bv *BlindVerify) Sig() *coconut.Signature {
	return bv.sig
}

func (bv *BlindVerify) PubM() []*Curve.BIG {
	return bv.pubM
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (bv *BlindVerify) UnmarshalBinary(data []byte) error {
	blen := constants.BIGLen
	eclen := constants.ECPLen

	pubMLength := data[0]
	pubM := make([]*Curve.BIG, pubMLength)
	for i := range pubM {
		pubM[i] = Curve.FromBytes(data[1+i*blen:])
	}

	sig := &coconut.Signature{}
	err := sig.UnmarshalBinary(data[1+len(pubM)*blen : 1+len(pubM)*blen+2*eclen])
	if err != nil {
		return err
	}

	blindShowMats := &coconut.BlindShowMats{}
	err = blindShowMats.UnmarshalBinary(data[1+len(pubM)*blen+2*eclen:])
	if err != nil {
		return err
	}

	bv.blindShowMats = blindShowMats
	bv.sig = sig
	bv.pubM = pubM
	bv.pubMLength = pubMLength

	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (bv *BlindVerify) MarshalBinary() ([]byte, error) {
	blen := constants.BIGLen
	eclen := constants.ECPLen

	bsmData, err := bv.blindShowMats.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, len(bsmData)+2*eclen+len(bv.pubM)*blen+1)
	data[0] = bv.pubMLength
	for i := range bv.pubM {
		bv.pubM[i].ToBytes(data[1+i*blen:])
	}
	sigData, err := bv.sig.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[1+len(bv.pubM)*blen:], sigData)
	copy(data[1+len(bv.pubM)*blen+2*eclen:], bsmData)

	return data, nil
}

func NewBlindVerify(blindShowMats *coconut.BlindShowMats, sig *coconut.Signature, pubM []*Curve.BIG) *BlindVerify {
	if len(pubM) > 255 {
		return nil
	}
	return &BlindVerify{
		sig:           sig,
		blindShowMats: blindShowMats,
		pubM:          pubM,
		pubMLength:    uint8(len(pubM)),
	}
}
