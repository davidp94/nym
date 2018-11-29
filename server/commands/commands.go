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
	"errors"

	"github.com/golang/protobuf/proto"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// todo: once everything works with protobuf simplify everything by removing the alternative

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
	// basically generated protocol buffer messages
	Reset()
	String() string
	ProtoMessage()
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

// CommandRequest defines set of Command and chan that is used by client workers.
type CommandRequest struct {
	cmd   Command
	retCh chan *Response
}

// NewCommandRequest creates new instance of CommandRequest.
func NewCommandRequest(cmd Command, ch chan *Response) *CommandRequest {
	return &CommandRequest{cmd: cmd, retCh: ch}
}

// RetCh returns return channel of CommandRequest.
func (cr *CommandRequest) RetCh() chan *Response {
	return cr.retCh
}

// Cmd returns command of CommandRequest.
func (cr *CommandRequest) Cmd() Command {
	return cr.cmd
}

type Response struct {
	Data         interface{}
	ErrorStatus  StatusCode
	ErrorMessage string
}

// FromBytes creates a given Command object out of stream of bytes.
func FromBytes(b []byte) (Command, error) {
	id := CommandID(b[0])
	payload := b[1:]
	var cmd Command
	switch id {
	case GetVerificationKeyID:
		cmd = &VerificationKeyRequest{}
	case SignID:
		cmd = &SignRequest{}
	case VerifyID:
		cmd = &VerifyRequest{}
	case BlindSignID:
		cmd = &BlindSignRequest{}
	case BlindVerifyID:
		cmd = &BlindVerifyRequest{}
	default:
		return nil, errors.New("Unknown CommandID")
	}

	if err := proto.Unmarshal(payload, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

type ProtoResponse interface {
	Reset()
	String() string
	ProtoMessage()
	GetStatus() *Status
}

func NewSignRequest(pubM []*Curve.BIG) (*SignRequest, error) {
	return &SignRequest{
		PubM: coconut.BigSliceToProto(pubM),
	}, nil
}

func NewVerificationKeyRequest() (*VerificationKeyRequest, error) {
	return &VerificationKeyRequest{}, nil
}

func NewVerifyRequest(pubM []*Curve.BIG, sig *coconut.Signature) (*VerifyRequest, error) {
	protoSig, err := sig.ToProto()
	if err != nil {
		return nil, err
	}
	return &VerifyRequest{
		Sig:  protoSig,
		PubM: coconut.BigSliceToProto(pubM),
	}, nil
}

func NewBlindSignRequest(blindSignMats *coconut.BlindSignMats, egPub *elgamal.PublicKey, pubM []*Curve.BIG) (*BlindSignRequest, error) {
	protoBlindSignMats, err := blindSignMats.ToProto()
	if err != nil {
		return nil, err
	}
	protoEgPub, err := egPub.ToProto()
	if err != nil {
		return nil, err
	}
	return &BlindSignRequest{
		BlindSignMats: protoBlindSignMats,
		EgPub:         protoEgPub,
		PubM:          coconut.BigSliceToProto(pubM),
	}, nil
}

func NewBlindVerifyRequest(blindShowMats *coconut.BlindShowMats, sig *coconut.Signature, pubM []*Curve.BIG) (*BlindVerifyRequest, error) {
	protoSig, err := sig.ToProto()
	if err != nil {
		return nil, err
	}
	protoBlindShowMats, err := blindShowMats.ToProto()
	if err != nil {
		return nil, err
	}
	return &BlindVerifyRequest{
		BlindShowMats: protoBlindShowMats,
		Sig:           protoSig,
		PubM:          coconut.BigSliceToProto(pubM),
	}, nil
}
