// auxiliary.go - set of auxiliary functions for the Coconut scheme.
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

// Package coconut provides the functionalities required by the Coconut Scheme.
package coconut

import (
	"errors"
	"strings"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	proto "github.com/golang/protobuf/proto"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// getBaseFromAttributes generates the base h from public attributes.
// It is only used for Sign function that works exlusively on public attributes
func getBaseFromAttributes(pubM []*Curve.BIG) (*Curve.ECP, error) {
	s := make([]string, len(pubM))
	for i := range pubM {
		s[i] = utils.ToCoconutString(pubM[i])
	}
	return utils.HashStringToG1(amcl.SHA512, strings.Join(s, ","))
}

// ValidateKeyPair checks if the coconut keypair was correctly formed.
func ValidateKeyPair(sk *SecretKey, vk *VerificationKey) bool {
	if len(sk.y) != len(vk.beta) || !sk.Validate() || !vk.Validate() {
		return false
	}
	if !vk.alpha.Equals(Curve.G2mul(vk.g2, sk.x)) {
		return false
	}
	for i := range sk.y {
		if !vk.beta[i].Equals(Curve.G2mul(vk.g2, sk.y[i])) {
			return false
		}
	}
	return true
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sk *SecretKey) MarshalBinary() ([]byte, error) {
	protoSk, err := sk.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoSk)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sk *SecretKey) UnmarshalBinary(data []byte) error {
	protoSk := &ProtoSecretKey{}
	if err := proto.Unmarshal(data, protoSk); err != nil {
		return err
	}
	return sk.FromProto(protoSk)
}

// ToProto creates a protobuf representation of the object.
func (sk *SecretKey) ToProto() (*ProtoSecretKey, error) {
	if !sk.Validate() {
		return nil, errors.New("the secret key is malformed")
	}
	blen := constants.BIGLen
	xb := make([]byte, blen)
	sk.x.ToBytes(xb)
	yb := make([][]byte, len(sk.y))
	for i := range yb {
		yb[i] = make([]byte, blen)
		sk.y[i].ToBytes(yb[i])
	}
	return &ProtoSecretKey{
		X: xb,
		Y: yb,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (sk *SecretKey) FromProto(psk *ProtoSecretKey) error {
	blen := constants.BIGLen
	if psk == nil || len(psk.X) != blen {
		return errors.New("invalid proto secret key")
	}
	x := Curve.FromBytes(psk.X)
	y := make([]*Curve.BIG, len(psk.Y))
	for i := range y {
		if len(psk.Y[i]) != blen {
			return errors.New("invalid proto secret key")
		}
		y[i] = Curve.FromBytes(psk.Y[i])
	}
	sk.x = x
	sk.y = y
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (vk *VerificationKey) MarshalBinary() ([]byte, error) {
	protoVk, err := vk.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoVk)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (vk *VerificationKey) UnmarshalBinary(data []byte) error {
	protoVk := &ProtoVerificationKey{}
	if err := proto.Unmarshal(data, protoVk); err != nil {
		return err
	}
	return vk.FromProto(protoVk)
}

// ToProto creates a protobuf representation of the object.
func (vk *VerificationKey) ToProto() (*ProtoVerificationKey, error) {
	if !vk.Validate() {
		return nil, errors.New("the verification key is malformed")
	}
	ec2len := constants.ECP2Len
	g2b := make([]byte, ec2len)
	alphab := make([]byte, ec2len)
	betab := make([][]byte, len(vk.Beta()))
	for i := range betab {
		betab[i] = make([]byte, ec2len)
		vk.Beta()[i].ToBytes(betab[i])
	}
	vk.G2().ToBytes(g2b)
	vk.Alpha().ToBytes(alphab)
	return &ProtoVerificationKey{
		G2:    g2b,
		Alpha: alphab,
		Beta:  betab,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (vk *VerificationKey) FromProto(pvk *ProtoVerificationKey) error {
	ec2len := constants.ECP2Len
	if pvk == nil || len(pvk.G2) != ec2len || len(pvk.Alpha) != ec2len || len(pvk.Beta) <= 0 {
		return errors.New("invalid proto verification key")
	}
	g2 := Curve.ECP2_fromBytes(pvk.G2)
	alpha := Curve.ECP2_fromBytes(pvk.Alpha)
	beta := make([]*Curve.ECP2, len(pvk.Beta))
	for i := range pvk.Beta {
		if len(pvk.Beta[i]) != ec2len {
			return errors.New("invalid proto verification key")
		}
		beta[i] = Curve.ECP2_fromBytes(pvk.Beta[i])
	}
	vk.g2 = g2
	vk.alpha = alpha
	vk.beta = beta
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sig *Signature) MarshalBinary() ([]byte, error) {
	protoSig, err := sig.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoSig)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sig *Signature) UnmarshalBinary(data []byte) error {
	protoSig := &ProtoSignature{}
	if err := proto.Unmarshal(data, protoSig); err != nil {
		return err
	}
	return sig.FromProto(protoSig)
}

// ToProto creates a protobuf representation of the object.
func (sig *Signature) ToProto() (*ProtoSignature, error) {
	if !sig.Validate() {
		return nil, errors.New("the signature is malformed")
	}
	eclen := constants.ECPLen
	sig1b := make([]byte, eclen)
	sig2b := make([]byte, eclen)
	sig.sig1.ToBytes(sig1b, true)
	sig.sig2.ToBytes(sig2b, true)
	return &ProtoSignature{
		Sig1: sig1b,
		Sig2: sig2b,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (sig *Signature) FromProto(psig *ProtoSignature) error {
	eclen := constants.ECPLen
	if psig == nil || len(psig.Sig1) != eclen || len(psig.Sig2) != eclen {
		return errors.New("invalid proto signature")
	}
	sig.sig1 = Curve.ECP_fromBytes(psig.Sig1)
	sig.sig2 = Curve.ECP_fromBytes(psig.Sig2)
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (bs *BlindedSignature) MarshalBinary() ([]byte, error) {
	protoBlindedSig, err := bs.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoBlindedSig)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (bs *BlindedSignature) UnmarshalBinary(data []byte) error {
	protoBlindedSig := &ProtoBlindedSignature{}
	if err := proto.Unmarshal(data, protoBlindedSig); err != nil {
		return err
	}
	return bs.FromProto(protoBlindedSig)
}

// ToProto creates a protobuf representation of the object.
func (bs *BlindedSignature) ToProto() (*ProtoBlindedSignature, error) {
	if !bs.Validate() {
		return nil, errors.New("the blinded signature is malformed")
	}
	eclen := constants.ECPLen

	sig1b := make([]byte, eclen)
	bs.sig1.ToBytes(sig1b, true)
	sig2TildaProto, err := bs.sig2Tilda.ToProto()
	if err != nil {
		return nil, err
	}
	return &ProtoBlindedSignature{
		Sig1:      sig1b,
		Sig2Tilda: sig2TildaProto,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (bs *BlindedSignature) FromProto(pbs *ProtoBlindedSignature) error {
	eclen := constants.ECPLen
	if pbs == nil || len(pbs.Sig1) != eclen {
		return errors.New("invalid proto blinded signature")
	}
	sig1 := Curve.ECP_fromBytes(pbs.Sig1)
	enc := &elgamal.Encryption{}
	if err := enc.FromProto(pbs.Sig2Tilda); err != nil {
		return err
	}

	bs.sig1 = sig1
	bs.sig2Tilda = enc
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sp *SignerProof) MarshalBinary() ([]byte, error) {
	protoSignerProof, err := sp.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoSignerProof)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sp *SignerProof) UnmarshalBinary(data []byte) error {
	protoSignerProof := &ProtoSignerProof{}
	if err := proto.Unmarshal(data, protoSignerProof); err != nil {
		return err
	}
	return sp.FromProto(protoSignerProof)
}

// ToProto creates a protobuf representation of the object.
func (sp *SignerProof) ToProto() (*ProtoSignerProof, error) {
	if !sp.Validate() {
		return nil, errors.New("the signer proof is malformed")
	}
	blen := constants.BIGLen
	cb := make([]byte, blen)
	rrb := make([]byte, blen)
	rkb := make([][]byte, len(sp.rk))
	rmb := make([][]byte, len(sp.rm))
	sp.c.ToBytes(cb)
	sp.rr.ToBytes(rrb)
	for i := range rkb {
		rkb[i] = make([]byte, blen)
		sp.rk[i].ToBytes(rkb[i])
	}
	for i := range rmb {
		rmb[i] = make([]byte, blen)
		sp.rm[i].ToBytes(rmb[i])
	}
	return &ProtoSignerProof{
		C:  cb,
		Rr: rrb,
		Rk: rkb,
		Rm: rmb,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (sp *SignerProof) FromProto(psp *ProtoSignerProof) error {
	blen := constants.BIGLen
	if psp == nil || len(psp.C) != blen || len(psp.Rr) != blen || psp.Rk == nil || psp.Rm == nil {
		return errors.New("invalid proto signer proof")
	}
	c := Curve.FromBytes(psp.C)
	rr := Curve.FromBytes(psp.Rr)
	rk := make([]*Curve.BIG, len(psp.Rk))
	rm := make([]*Curve.BIG, len(psp.Rm))
	for i := range psp.Rk {
		if len(psp.Rk[i]) != blen {
			return errors.New("invalid proto signer proof")
		}
		rk[i] = Curve.FromBytes(psp.Rk[i])
	}
	for i := range psp.Rm {
		if len(psp.Rm[i]) != blen {
			return errors.New("invalid proto signer proof")
		}
		rm[i] = Curve.FromBytes(psp.Rm[i])
	}
	sp.c = c
	sp.rr = rr
	sp.rk = rk
	sp.rm = rm
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (bsm *BlindSignMats) MarshalBinary() ([]byte, error) {
	protoBlindSignMats, err := bsm.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoBlindSignMats)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (bsm *BlindSignMats) UnmarshalBinary(data []byte) error {
	protoBlindSignMats := &ProtoBlindSignMats{}
	if err := proto.Unmarshal(data, protoBlindSignMats); err != nil {
		return err
	}
	return bsm.FromProto(protoBlindSignMats)
}

// ToProto creates a protobuf representation of the object.
func (bsm *BlindSignMats) ToProto() (*ProtoBlindSignMats, error) {
	if !bsm.Validate() {
		return nil, errors.New("the blind sign mats are malformed")
	}
	eclen := constants.ECPLen

	cmb := make([]byte, eclen)
	bsm.cm.ToBytes(cmb, true)

	enc := make([]*elgamal.ProtoEncryption, len(bsm.enc))
	for i := range enc {
		protoEnc, err := bsm.enc[i].ToProto()
		if err != nil {
			return nil, err
		}
		enc[i] = protoEnc
	}

	protoSignerProof, err := bsm.proof.ToProto()
	if err != nil {
		return nil, err
	}

	return &ProtoBlindSignMats{
		Cm:    cmb,
		Enc:   enc,
		Proof: protoSignerProof,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (bsm *BlindSignMats) FromProto(pbsm *ProtoBlindSignMats) error {
	eclen := constants.ECPLen
	if pbsm == nil || len(pbsm.Cm) != eclen {
		return errors.New("invalid proto blind sign mats")
	}
	cm := Curve.ECP_fromBytes(pbsm.Cm)
	enc := make([]*elgamal.Encryption, len(pbsm.Enc))
	for i := range enc {
		enci := &elgamal.Encryption{}
		if err := enci.FromProto(pbsm.Enc[i]); err != nil {
			return err
		}
		enc[i] = enci
	}
	proof := &SignerProof{}
	if err := proof.FromProto(pbsm.Proof); err != nil {
		return err
	}
	bsm.cm = cm
	bsm.enc = enc
	bsm.proof = proof
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (vp *VerifierProof) MarshalBinary() ([]byte, error) {
	protoVerifierProof, err := vp.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoVerifierProof)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (vp *VerifierProof) UnmarshalBinary(data []byte) error {
	protoVerifierProof := &ProtoVerifierProof{}
	if err := proto.Unmarshal(data, protoVerifierProof); err != nil {
		return err
	}
	return vp.FromProto(protoVerifierProof)
}

// ToProto creates a protobuf representation of the object.
func (vp *VerifierProof) ToProto() (*ProtoVerifierProof, error) {
	if vp == nil || vp.c == nil || vp.rm == nil || vp.rt == nil {
		return nil, errors.New("the verifier proof is malformed")
	}
	blen := constants.BIGLen
	cb := make([]byte, blen)
	vp.c.ToBytes(cb)

	rmb := make([][]byte, len(vp.rm))
	for i := range rmb {
		if vp.rm[i] == nil {
			return nil, errors.New("the verifier proof is malformed")
		}
		rmb[i] = make([]byte, blen)
		vp.rm[i].ToBytes(rmb[i])
	}

	rtb := make([]byte, blen)
	vp.rt.ToBytes(rtb)

	return &ProtoVerifierProof{
		C:  cb,
		Rm: rmb,
		Rt: rtb,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (vp *VerifierProof) FromProto(pvp *ProtoVerifierProof) error {
	blen := constants.BIGLen
	if pvp == nil || pvp.Rm == nil || len(pvp.C) != blen || len(pvp.Rt) != blen {
		return errors.New("invalid proto verifier proof")
	}
	c := Curve.FromBytes(pvp.C)
	rt := Curve.FromBytes(pvp.Rt)
	rm := make([]*Curve.BIG, len(pvp.Rm))
	for i := range pvp.Rm {
		if len(pvp.Rm[i]) != blen {
			return errors.New("invalid proto verifier proof")
		}
		rm[i] = Curve.FromBytes(pvp.Rm[i])
	}
	vp.c = c
	vp.rt = rt
	vp.rm = rm
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (bsm *BlindShowMats) MarshalBinary() ([]byte, error) {
	protoBlindShowMats, err := bsm.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoBlindShowMats)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (bsm *BlindShowMats) UnmarshalBinary(data []byte) error {
	protoBlindShowMats := &ProtoBlindShowMats{}
	if err := proto.Unmarshal(data, protoBlindShowMats); err != nil {
		return err
	}
	return bsm.FromProto(protoBlindShowMats)
}

// ToProto creates a protobuf representation of the object.
func (bsm *BlindShowMats) ToProto() (*ProtoBlindShowMats, error) {
	if bsm == nil || bsm.kappa == nil || bsm.nu == nil || bsm.proof == nil {
		return nil, errors.New("the blind show mats are malformed")
	}
	eclen := constants.ECPLen
	ec2len := constants.ECP2Len

	kappab := make([]byte, ec2len)
	bsm.kappa.ToBytes(kappab)
	nub := make([]byte, eclen)
	bsm.nu.ToBytes(nub, true)

	proof, err := bsm.proof.ToProto()
	if err != nil {
		return nil, err
	}

	return &ProtoBlindShowMats{
		Kappa: kappab,
		Nu:    nub,
		Proof: proof,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (bsm *BlindShowMats) FromProto(pbsm *ProtoBlindShowMats) error {
	eclen := constants.ECPLen
	ec2len := constants.ECP2Len
	if pbsm == nil || len(pbsm.Kappa) != ec2len || len(pbsm.Nu) != eclen {
		return errors.New("invalid proto blind show mats")
	}
	kappa := Curve.ECP2_fromBytes(pbsm.Kappa)
	nu := Curve.ECP_fromBytes(pbsm.Nu)
	proof := &VerifierProof{}
	if err := proof.FromProto(pbsm.Proof); err != nil {
		return err
	}
	bsm.kappa = kappa
	bsm.nu = nu
	bsm.proof = proof
	return nil
}

// BigSliceFromByteSlices recovers a slice of BIG nums from a slice of slices of bytes.
func BigSliceFromByteSlices(b [][]byte) []*Curve.BIG {
	bigs := make([]*Curve.BIG, len(b))
	for i := range b {
		bigs[i] = Curve.FromBytes(b[i])
	}
	return bigs
}

// BigSliceToByteSlices converts a slice of BIG nums to slice of slices of bytes.
func BigSliceToByteSlices(s []*Curve.BIG) ([][]byte, error) {
	// need to allow encoding empty (not nil) slices for blindsign of 0 public attrs
	if s == nil {
		return nil, errors.New("invalid BIG slice provided")
	}
	blen := constants.BIGLen
	b := make([][]byte, len(s))
	for i := range b {
		if s[i] == nil {
			return nil, errors.New("nil element in slice present")
		}
		b[i] = make([]byte, blen)
		s[i].ToBytes(b[i])
	}
	return b, nil
}

// ValidateBigSlice checks if the slice of BIG nums contain no nil elements.
func ValidateBigSlice(s []*Curve.BIG) bool {
	if s == nil {
		return false
	}
	for i := range s {
		if s[i] == nil {
			return false
		}
	}
	return true
}
