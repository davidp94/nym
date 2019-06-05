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
	"errors"

	cmnutils "0xacab.org/jstuczyn/CoconutGo/common/utils"
	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	proto "github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

var (
	// ErrUnmarshalLength represents an error thrown during unmarshal when the byte arrays have unexpected lengths.
	ErrUnmarshalLength = errors.New("the byte array provided is incomplete")
)

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	// Both p and g are redundant as they are implied from the curve used, but are introduced for consistency sake.
	p     *Curve.BIG
	g     *Curve.ECP
	gamma *Curve.ECP
}

// P returns the appropriate part of the ElGamal public key.
func (pub *PublicKey) P() *Curve.BIG {
	return pub.p
}

// G returns the appropriate part of the ElGamal public key.
func (pub *PublicKey) G() *Curve.ECP {
	return pub.g
}

// Gamma returns the appropriate part of the ElGamal public key.
func (pub *PublicKey) Gamma() *Curve.ECP {
	return pub.gamma
}

// NewPublicKey returns new instance of ElGamal public key with the provided arguments.
func NewPublicKey(p *Curve.BIG, g *Curve.ECP, gamma *Curve.ECP) *PublicKey {
	return &PublicKey{
		p:     p,
		g:     g,
		gamma: gamma,
	}
}

// PrivateKey represents an ElGamal private key.
type PrivateKey struct {
	d *Curve.BIG
}

// D returns the appropriate part of the ElGamal private key.
func (pk *PrivateKey) D() *Curve.BIG {
	return pk.d
}

// NewPrivateKey returns new instance of ElGamal private key with the provided argument.
func NewPrivateKey(d *Curve.BIG) *PrivateKey {
	return &PrivateKey{
		d: d,
	}
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
	if pub == nil || pub.p == nil || pub.g == nil || pub.gamma == nil {
		return nil, errors.New("the elgamal public key is malformed")
	}
	blen := constants.BIGLen
	eclen := constants.ECPLen
	pb := make([]byte, blen)
	gb := make([]byte, eclen)
	gammab := make([]byte, eclen)
	pub.p.ToBytes(pb)
	pub.g.ToBytes(gb, true)
	pub.gamma.ToBytes(gammab, true)
	return &ProtoPublicKey{
		P:     pb,
		G:     gb,
		Gamma: gammab,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (pub *PublicKey) FromProto(ppub *ProtoPublicKey) error {
	blen := constants.BIGLen
	eclen := constants.ECPLen
	if ppub == nil || len(ppub.P) != blen || len(ppub.G) != eclen || len(ppub.Gamma) != eclen {
		return errors.New("invalid proto elgamal public key")
	}
	pub.p = Curve.FromBytes(ppub.P)
	pub.g = Curve.ECP_fromBytes(ppub.G)
	pub.gamma = Curve.ECP_fromBytes(ppub.Gamma)
	return nil
}

// ToPEMFile writes out the verification key to a PEM file at path f.
func (pub *PublicKey) ToPEMFile(f string) error {
	return cmnutils.ToPEMFile(pub, f, constants.ElGamalPublicKeyType)
}

// FromPEMFile reads out the secret key from a PEM file at path f.
func (pub *PublicKey) FromPEMFile(f string) error {
	return cmnutils.FromPEMFile(pub, f, constants.ElGamalPublicKeyType)
}

// Validate checks for nil elements in the key.
func (pub *PublicKey) Validate() bool {
	if pub == nil || pub.g == nil || pub.gamma == nil || pub.p == nil {
		return false
	}

	expg := Curve.ECP_generator()
	expp := Curve.NewBIGints(Curve.CURVE_Order)

	if !pub.g.Equals(expg) || Curve.Comp(expp, pub.p) != 0 {
		return false
	}
	return true
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
	return cmnutils.ToPEMFile(pk, f, constants.ElGamalPrivateKeyType)
}

// ToProto creates a protobuf representation of the object.
func (pk *PrivateKey) ToProto() (*ProtoPrivateKey, error) {
	if pk == nil || pk.d == nil {
		return nil, errors.New("the elgamal private key is malformed")
	}
	blen := constants.BIGLen
	db := make([]byte, blen)
	pk.d.ToBytes(db)
	return &ProtoPrivateKey{
		D: db,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (pk *PrivateKey) FromProto(ppk *ProtoPrivateKey) error {
	blen := constants.BIGLen
	if ppk == nil || len(ppk.D) != blen {
		return errors.New("invalid proto elgamal private key")
	}
	pk.d = Curve.FromBytes(ppk.D)
	return nil
}

// FromPEMFile reads out the secret key from a PEM file at path f.
func (pk *PrivateKey) FromPEMFile(f string) error {
	return cmnutils.FromPEMFile(pk, f, constants.ElGamalPrivateKeyType)
}

// Validate checks for nil elements in the key.
func (pk *PrivateKey) Validate() bool {
	if pk == nil || pk.d == nil {
		return false
	}
	return true
}

// ValidateKeyPair checks if the ElGamal keypair was correctly formed.
func ValidateKeyPair(pk *PrivateKey, pub *PublicKey) bool {
	return pk.Validate() && pub.Validate() && pub.gamma.Equals(Curve.G1mul(pub.g, pk.d))
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
	if e == nil || e.c1 == nil || e.c2 == nil {
		return nil, errors.New("the elgamal encryption is malformed")
	}
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
	eclen := constants.ECPLen
	if pe == nil || len(pe.C1) != eclen || len(pe.C2) != eclen {
		return errors.New("invalid proto encryption")
	}
	e.c1 = Curve.ECP_fromBytes(pe.C1)
	e.c2 = Curve.ECP_fromBytes(pe.C2)
	return nil
}

// Validate checks for nil elements in the encryption.
func (e *Encryption) Validate() bool {
	if e == nil || e.c1 == nil || e.c2 == nil {
		return false
	}
	return true
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
func Keygen(g *bpgroup.BpGroup) (*PrivateKey, *PublicKey) {
	p, g1, rng := g.Order(), g.Gen1(), g.Rng()

	d := Curve.Randomnum(p, rng)
	gamma := Curve.G1mul(g1, d)
	return &PrivateKey{d: d}, &PublicKey{p: p, g: g1, gamma: gamma}
}

// Encrypt encrypts the given message in the form of h^m,
// where h is a point on the G1 curve using the given public key.
// The random k is returned alongside the encryption
// as it is required by the Coconut Scheme to create proofs of knowledge.
func Encrypt(g *bpgroup.BpGroup, pub *PublicKey, m *Curve.BIG, h *Curve.ECP) (*Encryption, *Curve.BIG) {
	gamma, p, g1, rng := pub.gamma, pub.p, pub.g, g.Rng()

	k := Curve.Randomnum(p, rng)
	a := Curve.G1mul(g1, k)
	b := Curve.G1mul(gamma, k) // b = (k * gamma)
	b.Add(Curve.G1mul(h, m))   // b = (k * gamma) + (m * h)

	return &Encryption{a, b}, k
}

// Decrypt takes the ElGamal encryption of a message and returns a point on the G1 curve
// that represents original h^m.
func Decrypt(g *bpgroup.BpGroup, pk *PrivateKey, enc *Encryption) *Curve.ECP {
	d := pk.d

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

// PublicKeyFromPrivate returns a public key instance corresponding to the provided private key.
func PublicKeyFromPrivate(pk *PrivateKey) *PublicKey {
	g := Curve.ECP_generator()
	return &PublicKey{
		p:     Curve.NewBIGints(Curve.CURVE_Order),
		g:     g,
		gamma: Curve.G1mul(g, pk.d),
	}
}
