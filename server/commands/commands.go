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
	"github.com/jstuczyn/CoconutGo/crypto/elgamal"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const (
	// GetVerificationKeyID is commandID for getting server's verification key.
	GetVerificationKeyID CommandID = 100

	// SignID is commandID for signing public attributes.
	SignID CommandID = 101

	// VerifyID is commandID for verifying a signature on public attributes.
	VerifyID CommandID = 102

	// BlindSignID is commandID for blindly signing public and private attributes.
	BlindSignID CommandID = 103

	// BlindVerifyID is commandID for verifying a blind signature on public and private attributes.
	BlindVerifyID CommandID = 104
)

// Command defines interface that is implemented by all commands defined in the package.
// todo: is this really restrictive enough?
type Command interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(data []byte) error
}

// CommandID is wrapper for a byte defining ID of particular command.
type CommandID byte

// RawCommand encapsulates arbitrary marshaled command and ID that defines it.
type RawCommand struct {
	id      CommandID
	payload []byte
}

// NewRawCommand creates new instance of RawCommand given ID and its payload.
func NewRawCommand(id CommandID, payload []byte) *RawCommand {
	return &RawCommand{id, payload}
}

// ID returns CommandID of RawCommand.
func (c *RawCommand) ID() CommandID {
	return c.id
}

// Payload returns Payload of RawCommand.
func (c *RawCommand) Payload() []byte {
	return c.payload
}

// ToBytes marshals RawCommand into a stream of bytes so that it could be turned into a packet.
func (c *RawCommand) ToBytes() []byte {
	b := make([]byte, 1+len(c.payload))
	b[0] = byte(c.id)
	copy(b[1:], c.payload)
	return b
}

// FromBytes creates a given Command object out of stream of bytes.
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

// CommandRequest defines set of Command and chan that is used by client workers.
type CommandRequest struct {
	cmd   Command
	retCh chan interface{}
}

// NewCommandRequest creates new instance of CommandRequest.
func NewCommandRequest(cmd Command, ch chan interface{}) *CommandRequest {
	return &CommandRequest{cmd: cmd, retCh: ch}
}

// RetCh returns return channel of CommandRequest.
func (cr *CommandRequest) RetCh() chan interface{} {
	return cr.retCh
}

// Cmd returns command of CommandRequest.
func (cr *CommandRequest) Cmd() Command {
	return cr.cmd
}

// all the below commands are recovered from payload field in Command
// id is used to determine which one to recover

// Sign defines required parameters to perform a sign on public attributes.
type Sign struct {
	pubM []*Curve.BIG
}

// PubM returns set of public attributes from Sign command.
func (s *Sign) PubM() []*Curve.BIG {
	return s.pubM
}

// NewSign returns new instance of Sign command.
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

// Vk defines required parameters to perform a GetVerificationKey command
// (which are none)
type Vk struct{}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (v *Vk) UnmarshalBinary(data []byte) error { return nil }

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (v *Vk) MarshalBinary() ([]byte, error) { return make([]byte, 0), nil }

// Verify defines required parameters to perform a verification of signature on public attributes.
type Verify struct {
	sig  *coconut.Signature
	pubM []*Curve.BIG
}

// Sig returns signature from Verify command.
func (v *Verify) Sig() *coconut.Signature {
	return v.sig
}

// PubM returns public attributes from Verify command.
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

// NewVerify returns new instance of Verify command.
func NewVerify(pubM []*Curve.BIG, sig *coconut.Signature) *Verify {
	return &Verify{
		pubM: pubM,
		sig:  sig,
	}
}

// BlindSign defines required parameters to perform a blind sign on private and public attributes.
type BlindSign struct {
	blindSignMats *coconut.BlindSignMats
	egPub         *elgamal.PublicKey
	pubM          []*Curve.BIG
	pubMLength    uint8 // 1 byte of overhead to significantly simplify marshaling/unmarshaling
}

// BlindSignMats returns BlindSignMats part of BlindSign command.
func (bs *BlindSign) BlindSignMats() *coconut.BlindSignMats {
	return bs.blindSignMats
}

// // Gamma returns Gamma part of BlindSign command.
// func (bs *BlindSign) Gamma() *Curve.ECP {
// 	return bs.gamma
// }

// EgPub returns client's ElGamal Public Key
func (bs *BlindSign) EgPub() *elgamal.PublicKey {
	return bs.egPub
}

// PubM returns PubM part of BlindSign command.
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
	egPub := &elgamal.PublicKey{}
	err := egPub.UnmarshalBinary(data[1+len(pubM)*blen:])
	if err != nil {
		return err
	}

	blindSignMats := &coconut.BlindSignMats{}
	err = blindSignMats.UnmarshalBinary(data[1+(1+len(pubM))*blen+2*eclen:])
	if err != nil {
		return err
	}
	bs.blindSignMats = blindSignMats
	bs.egPub = egPub
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
	data := make([]byte, len(bsmData)+2*eclen+(1+len(bs.pubM))*blen+1)
	data[0] = bs.pubMLength
	for i := range bs.pubM {
		bs.pubM[i].ToBytes(data[1+i*blen:])
	}

	egPubData, err := bs.egPub.MarshalBinary()
	if err != nil {
		return nil, err
	}

	copy(data[1+len(bs.pubM)*blen:], egPubData)
	copy(data[1+(1+len(bs.pubM))*blen+2*eclen:], bsmData)

	return data, nil
}

// NewBlindSign returns new instance of a BlindSign command.
func NewBlindSign(blindSignMats *coconut.BlindSignMats, egPub *elgamal.PublicKey, pubM []*Curve.BIG) *BlindSign {
	if len(pubM) > 255 {
		return nil
	}
	return &BlindSign{
		blindSignMats: blindSignMats,
		egPub:         egPub,
		pubM:          pubM,
		pubMLength:    uint8(len(pubM)),
	}
}

// BlindVerify defines required parameters to perform a verification of blind signature on private and public attributes
type BlindVerify struct {
	sig           *coconut.Signature
	blindShowMats *coconut.BlindShowMats
	pubM          []*Curve.BIG
	pubMLength    uint8 // 1 byte of overhead to significantly simplify marshaling/unmarshaling
}

// BlindShowMats returns BlindShowMats part of BlindVerify command.
func (bv *BlindVerify) BlindShowMats() *coconut.BlindShowMats {
	return bv.blindShowMats
}

// Sig returns Sig part of BlindVerify command.
func (bv *BlindVerify) Sig() *coconut.Signature {
	return bv.sig
}

// PubM returns PubM part of BlindVerify command.
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

// NewBlindVerify returns new instance of a BlindVerify command.
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
