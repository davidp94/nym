// marshal.go - defines methods for marshaling and unmarshaling coconut structures.
// Copyright (C) 2019  Jedrzej Stuczynski.
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

	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	proto "github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (params *Params) MarshalBinary() ([]byte, error) {
	protoParams, err := params.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoParams)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (params *Params) UnmarshalBinary(data []byte) error {
	protoParams := &ProtoParams{}
	if err := proto.Unmarshal(data, protoParams); err != nil {
		return err
	}
	return params.FromProto(protoParams)
}

// ToProto creates a protobuf representation of the object.
func (params *Params) ToProto() (*ProtoParams, error) {
	if !params.Validate() {
		return nil, errors.New("the params are malformed")
	}
	blen := constants.BIGLen
	eclen := constants.ECPLen
	ec2len := constants.ECP2Len

	pb := make([]byte, blen)
	g1b := make([]byte, eclen)
	g2b := make([]byte, ec2len)
	hsb := make([][]byte, len(params.hs))

	params.p.ToBytes(pb)
	params.g1.ToBytes(g1b, true)
	params.g2.ToBytes(g2b)

	for i := range hsb {
		hsb[i] = make([]byte, eclen)
		params.hs[i].ToBytes(hsb[i], true)
	}
	return &ProtoParams{
		P:  pb,
		G1: g1b,
		G2: g2b,
		Hs: hsb,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (params *Params) FromProto(pp *ProtoParams) error {
	blen := constants.BIGLen
	eclen := constants.ECPLen
	ec2len := constants.ECP2Len

	if pp == nil || len(pp.P) != blen || len(pp.G1) != eclen || len(pp.G2) != ec2len {
		return errors.New("invalid proto params")
	}

	p := Curve.FromBytes(pp.P)
	g1 := Curve.ECP_fromBytes(pp.G1)
	g2 := Curve.ECP2_fromBytes(pp.G2)
	hs := make([]*Curve.ECP, len(pp.Hs))
	for i := range hs {
		if len(pp.Hs[i]) != eclen {
			return errors.New("invalid proto params")
		}
		hs[i] = Curve.ECP_fromBytes(pp.Hs[i])
	}

	params.p = p
	params.g1 = g1
	params.g2 = g2
	params.hs = hs
	params.G = bpgroup.New()

	return nil
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
func (lambda *Lambda) MarshalBinary() ([]byte, error) {
	protoLambda, err := lambda.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoLambda)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (lambda *Lambda) UnmarshalBinary(data []byte) error {
	protoLambda := &ProtoLambda{}
	if err := proto.Unmarshal(data, protoLambda); err != nil {
		return err
	}
	return lambda.FromProto(protoLambda)
}

// ToProto creates a protobuf representation of the object.
func (lambda *Lambda) ToProto() (*ProtoLambda, error) {
	if !lambda.Validate() {
		return nil, errors.New("the blind sign mats are malformed")
	}
	eclen := constants.ECPLen

	cmb := make([]byte, eclen)
	lambda.cm.ToBytes(cmb, true)

	enc := make([]*elgamal.ProtoEncryption, len(lambda.enc))
	for i := range enc {
		protoEnc, err := lambda.enc[i].ToProto()
		if err != nil {
			return nil, err
		}
		enc[i] = protoEnc
	}

	protoSignerProof, err := lambda.proof.ToProto()
	if err != nil {
		return nil, err
	}

	return &ProtoLambda{
		Cm:    cmb,
		Enc:   enc,
		Proof: protoSignerProof,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (lambda *Lambda) FromProto(protoLambda *ProtoLambda) error {
	eclen := constants.ECPLen
	if protoLambda == nil || len(protoLambda.Cm) != eclen {
		return errors.New("invalid proto blind sign mats")
	}
	cm := Curve.ECP_fromBytes(protoLambda.Cm)
	enc := make([]*elgamal.Encryption, len(protoLambda.Enc))
	for i := range enc {
		enci := &elgamal.Encryption{}
		if err := enci.FromProto(protoLambda.Enc[i]); err != nil {
			return err
		}
		enc[i] = enci
	}
	proof := &SignerProof{}
	if err := proof.FromProto(protoLambda.Proof); err != nil {
		return err
	}
	lambda.cm = cm
	lambda.enc = enc
	lambda.proof = proof
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
func (theta *Theta) MarshalBinary() ([]byte, error) {
	ProtoTheta, err := theta.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(ProtoTheta)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (theta *Theta) UnmarshalBinary(data []byte) error {
	protoTheta := &ProtoTheta{}
	if err := proto.Unmarshal(data, protoTheta); err != nil {
		return err
	}
	return theta.FromProto(protoTheta)
}

// ToProto creates a protobuf representation of the object.
func (theta *Theta) ToProto() (*ProtoTheta, error) {
	if theta == nil || theta.kappa == nil || theta.nu == nil || theta.proof == nil {
		return nil, errors.New("the theta is malformed")
	}
	eclen := constants.ECPLen
	ec2len := constants.ECP2Len

	kappab := make([]byte, ec2len)
	theta.kappa.ToBytes(kappab)
	nub := make([]byte, eclen)
	theta.nu.ToBytes(nub, true)

	proof, err := theta.proof.ToProto()
	if err != nil {
		return nil, err
	}

	return &ProtoTheta{
		Kappa: kappab,
		Nu:    nub,
		Proof: proof,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (theta *Theta) FromProto(protoTheta *ProtoTheta) error {
	eclen := constants.ECPLen
	ec2len := constants.ECP2Len
	if protoTheta == nil || len(protoTheta.Kappa) != ec2len || len(protoTheta.Nu) != eclen {
		return errors.New("invalid proto theta")
	}
	kappa := Curve.ECP2_fromBytes(protoTheta.Kappa)
	nu := Curve.ECP_fromBytes(protoTheta.Nu)
	proof := &VerifierProof{}
	if err := proof.FromProto(protoTheta.Proof); err != nil {
		return err
	}
	theta.kappa = kappa
	theta.nu = nu
	theta.proof = proof
	return nil
}
