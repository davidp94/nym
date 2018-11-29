// elgamal.go - ElGamal encryption scheme
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

// Package elgamal provides primitives required by the ElGamal encryption scheme.
// It's based on Python's implementation: https://github.com/asonnino/coconut/blob/master/coconut/utils.py.
package elgamal

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	proto "github.com/golang/protobuf/proto"

	// The named import is used to be able to easily update curve being used
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// todo: create types for public and private keys and adjust arguments accordingly (look https://godoc.org/golang.org/x/crypto/openpgp/elgamal)
// todo: possibly alternative version of Decrypt to return actual m rather than h^m
// todo: should decrypt take BpGroup argument for the sake of consistency or just remove it?

// todo: move it somewhere else as the identical code is in coconut.auxiliary... cant reference it due to cyclic
// make separate packet for marshalling?
var (
	ErrUnmarshalLength = errors.New("The byte array provided is incomplete")
)

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	P     *Curve.BIG // this attribute is redundant as it is implied from the curve used, but is introduced for consistency sake.
	G     *Curve.ECP // this attribute is redundant as it is implied from the curve used, but is introduced for consistency sake.
	Gamma *Curve.ECP
}

// PrivateKey represents an ElGamal private key.
type PrivateKey struct {
	D *Curve.BIG
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	protoPub, err := pub.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoPub)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (pub *PublicKey) UnmarshalBinary(data []byte) error {
	protoPub := &ProtoPublicKey{}
	if err := proto.Unmarshal(data, protoPub); err != nil {
		return err
	}
	return pub.FromProto(protoPub)
}

// ToProto creates a protobuf representation of the object.
func (pub *PublicKey) ToProto() (*ProtoPublicKey, error) {
	blen := constants.BIGLen
	eclen := constants.ECPLen
	pb := make([]byte, blen)
	gb := make([]byte, eclen)
	gammab := make([]byte, eclen)
	pub.P.ToBytes(pb)
	pub.G.ToBytes(gb, true)
	pub.Gamma.ToBytes(gammab, true)
	return &ProtoPublicKey{
		P:     pb,
		G:     gb,
		Gamma: gammab,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (pub *PublicKey) FromProto(ppub *ProtoPublicKey) error {
	pub.P = Curve.FromBytes(ppub.P)
	pub.G = Curve.ECP_fromBytes(ppub.G)
	pub.Gamma = Curve.ECP_fromBytes(ppub.Gamma)
	return nil
}

// ToPEMFile writes out the verification key to a PEM file at path f.
func (pub *PublicKey) ToPEMFile(f string) error {
	b, err := pub.MarshalBinary()
	if err != nil {
		return err
	}
	blk := &pem.Block{
		Type:  constants.ElGamalPublicKeyType,
		Bytes: b,
	}
	return ioutil.WriteFile(f, pem.EncodeToMemory(blk), 0600)
}

// FromPEMFile reads out the secret key from a PEM file at path f.
func (pub *PublicKey) FromPEMFile(f string) error {
	if buf, err := ioutil.ReadFile(filepath.Clean(f)); err == nil {
		blk, rest := pem.Decode(buf)
		if len(rest) != 0 {
			return fmt.Errorf("trailing garbage after PEM encoded secret key")
		}
		if blk.Type != constants.ElGamalPublicKeyType {
			return fmt.Errorf("invalid PEM Type: '%v'", blk.Type)
		}
		if pub.UnmarshalBinary(blk.Bytes) != nil {
			return errors.New("failed to read public key from PEM file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (pk *PrivateKey) MarshalBinary() ([]byte, error) {
	protoPriv, err := pk.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoPriv)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (pk *PrivateKey) UnmarshalBinary(data []byte) error {
	protoPriv := &ProtoPrivateKey{}
	if err := proto.Unmarshal(data, protoPriv); err != nil {
		return err
	}
	return pk.FromProto(protoPriv)
}

// ToPEMFile writes out the secret key to a PEM file at path f.
func (pk *PrivateKey) ToPEMFile(f string) error {
	b, err := pk.MarshalBinary()
	if err != nil {
		return err
	}
	blk := &pem.Block{
		Type:  constants.ElGamalPrivateKeyType,
		Bytes: b,
	}
	return ioutil.WriteFile(f, pem.EncodeToMemory(blk), 0600)
}

// ToProto creates a protobuf representation of the object.
func (pk *PrivateKey) ToProto() (*ProtoPrivateKey, error) {
	blen := constants.BIGLen
	db := make([]byte, blen)
	pk.D.ToBytes(db)
	return &ProtoPrivateKey{
		D: db,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (pk *PrivateKey) FromProto(ppk *ProtoPrivateKey) error {
	pk.D = Curve.FromBytes(ppk.D)
	return nil
}

// FromPEMFile reads out the secret key from a PEM file at path f.
func (pk *PrivateKey) FromPEMFile(f string) error {
	if buf, err := ioutil.ReadFile(filepath.Clean(f)); err == nil {
		blk, rest := pem.Decode(buf)
		if len(rest) != 0 {
			return fmt.Errorf("trailing garbage after PEM encoded secret key")
		}
		if blk.Type != constants.ElGamalPrivateKeyType {
			return fmt.Errorf("invalid PEM Type: '%v'", blk.Type)
		}
		if pk.UnmarshalBinary(blk.Bytes) != nil {
			return errors.New("failed to read private key from PEM file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// EncryptionResult encapsulates entire result of ElGamal encryption, including random k.
type EncryptionResult struct {
	enc *Encryption
	k   *Curve.BIG
}

// Enc returns encryption part of the EncryptionResult.
func (er *EncryptionResult) Enc() *Encryption {
	return er.enc
}

// K returns random k part of the EncryptionResult.
func (er *EncryptionResult) K() *Curve.BIG {
	return er.k
}

// Encryption are the two points on the G1 curve
// that represent encryption of message in form of h^m.
type Encryption struct {
	c1 *Curve.ECP
	c2 *Curve.ECP
}

// C1 returns first group element of the ElGamal Encryption.
func (e *Encryption) C1() *Curve.ECP {
	return e.c1
}

// C2 returns second group element of the ElGamal Encryption.
func (e *Encryption) C2() *Curve.ECP {
	return e.c2
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (e *Encryption) MarshalBinary() ([]byte, error) {
	protoEnc, err := e.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoEnc)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (e *Encryption) UnmarshalBinary(data []byte) error {
	protoEnc := &ProtoEncryption{}
	if err := proto.Unmarshal(data, protoEnc); err != nil {
		return err
	}
	return e.FromProto(protoEnc)
}

// ToProto creates a protobuf representation of the object.
func (e *Encryption) ToProto() (*ProtoEncryption, error) {
	eclen := constants.ECPLen
	c1b := make([]byte, eclen)
	c2b := make([]byte, eclen)
	e.c1.ToBytes(c1b, true)
	e.c2.ToBytes(c2b, true)
	return &ProtoEncryption{
		C1: c1b,
		C2: c2b,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (e *Encryption) FromProto(pe *ProtoEncryption) error {
	e.c1 = Curve.ECP_fromBytes(pe.C1)
	e.c2 = Curve.ECP_fromBytes(pe.C2)
	return nil
}

// NewEncryptionFromPoints wraps two points on G1 curve as ElGamal Encryption.
func NewEncryptionFromPoints(c1 *Curve.ECP, c2 *Curve.ECP) *Encryption {
	return &Encryption{
		c1: c1,
		c2: c2,
	}
}

// Keygen generates private and public keys required for ElGamal encryption scheme.
// Passing coconut.Params as an argument would cause issues with cyclic dependencies,
// passing BpGroup in that case is sufficient.
func Keygen(G *bpgroup.BpGroup) (*PrivateKey, *PublicKey) {
	p, g1, rng := G.Order(), G.Gen1(), G.Rng()

	d := Curve.Randomnum(p, rng)
	gamma := Curve.G1mul(g1, d)
	return &PrivateKey{d}, &PublicKey{p, g1, gamma}
}

// Encrypt encrypts the given message in the form of h^m,
// where h is a point on the G1 curve using the given public key.
// The random k is returned alongside the encryption
// as it is required by the Coconut Scheme to create proofs of knowledge.
func Encrypt(G *bpgroup.BpGroup, pub *PublicKey, m *Curve.BIG, h *Curve.ECP) (*Encryption, *Curve.BIG) {
	gamma, p, g1, rng := pub.Gamma, pub.P, pub.G, G.Rng()

	k := Curve.Randomnum(p, rng)
	a := Curve.G1mul(g1, k)
	b := Curve.G1mul(gamma, k) // b = (k * gamma)
	b.Add(Curve.G1mul(h, m))   // b = (k * gamma) + (m * h)

	return &Encryption{a, b}, k
}

// Decrypt takes the ElGamal encryption of a message and returns a point on the G1 curve
// that represents original h^m.
func Decrypt(G *bpgroup.BpGroup, pk *PrivateKey, enc *Encryption) *Curve.ECP {
	d := pk.D

	dec := Curve.NewECP()
	dec.Copy(enc.c2)
	dec.Sub(Curve.G1mul(enc.c1, d))
	return dec
}

// NewEncryptionResult returns new instance of EncryptionResult from provided encryption and k.
func NewEncryptionResult(enc *Encryption, k *Curve.BIG) *EncryptionResult {
	return &EncryptionResult{
		enc: enc,
		k:   k,
	}
}
