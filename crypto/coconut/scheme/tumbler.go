// tumbler.go - Tumbler-related coconut functionalities
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
	fmt "fmt"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	proto "github.com/golang/protobuf/proto"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// TumblerProof is a special case of VerifierProof that is bound to some address
// and also encapsulates some zeta (g^s).
type TumblerProof struct {
	baseProof *VerifierProof
	zeta      *Curve.ECP
}

// BaseProof returns the base proof containing (c, rm, rt).
func (tp *TumblerProof) BaseProof() *VerifierProof {
	return tp.baseProof
}

// Zeta returns zeta used in the proof.
func (tp *TumblerProof) Zeta() *Curve.ECP {
	return tp.zeta
}

// Validate checks for nil elements in the proof.
func (tp *TumblerProof) Validate() bool {
	if tp == nil || tp.zeta == nil {
		return false
	}
	return tp.baseProof.Validate()
}

// NewTumblerProof returns instance of TumblerProof from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewTumblerProof(baseProof *VerifierProof, zeta *Curve.ECP) *TumblerProof {
	return &TumblerProof{
		baseProof: baseProof,
		zeta:      zeta,
	}
}

// ThetaTumbler encapsulates data created by ShowBlindSignatureTumbler function.
type ThetaTumbler struct {
	*Theta
	zeta *Curve.ECP
}

// Zeta returns the zeta part of the ThetaTumbler.
func (t *ThetaTumbler) Zeta() *Curve.ECP {
	return t.zeta
}

// Validate checks for nil elements in the mats.
func (t *ThetaTumbler) Validate() bool {
	if t.zeta == nil {
		return false
	}
	return t.Theta.Validate()
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (t *ThetaTumbler) MarshalBinary() ([]byte, error) {
	protoThetaTumbler, err := t.ToProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(protoThetaTumbler)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (t *ThetaTumbler) UnmarshalBinary(data []byte) error {
	protoThetaTumbler := &ProtoThetaTumbler{}
	if err := proto.Unmarshal(data, protoThetaTumbler); err != nil {
		return err
	}
	return t.FromProto(protoThetaTumbler)
}

// ToProto creates a protobuf representation of the object.
func (t *ThetaTumbler) ToProto() (*ProtoThetaTumbler, error) {
	if t == nil || t.zeta == nil || !t.Theta.Validate() {
		return nil, errors.New("thetaTumbler is malformed")
	}

	eclen := constants.ECPLen
	zetab := make([]byte, eclen)
	t.zeta.ToBytes(zetab, true)

	protoTheta, err := t.Theta.ToProto()
	if err != nil {
		return nil, err
	}

	return &ProtoThetaTumbler{
		Theta: protoTheta,
		Zeta:  zetab,
	}, nil
}

// FromProto takes a protobuf representation of the object and
// unmarshals its attributes.
func (t *ThetaTumbler) FromProto(protoThetaTumbler *ProtoThetaTumbler) error {
	eclen := constants.ECPLen
	if protoThetaTumbler == nil || len(protoThetaTumbler.Zeta) != eclen {
		return errors.New("invalid proto thetaTumbler")
	}

	zeta := Curve.ECP_fromBytes(protoThetaTumbler.Zeta)
	theta := &Theta{}
	if err := theta.FromProto(protoThetaTumbler.Theta); err != nil {
		return err
	}

	t.Theta = theta
	t.zeta = zeta
	return nil
}

// NewThetaTumbler returns instance of ThetaTumbler from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewThetaTumbler(theta *Theta, zeta *Curve.ECP) *ThetaTumbler {
	return &ThetaTumbler{
		Theta: theta,
		zeta:  zeta,
	}
}

// CreateBinding creates a binding to given byte sequence by either recovering it's direct value as ECP
// or by hashing it onto G1.
func CreateBinding(seq []byte) (*Curve.ECP, error) {
	if len(seq) <= 0 {
		return nil, errors.New("Nil or slice of length 0 provided")
	}
	var bind *Curve.ECP
	// if it is a bytes ECP just use that
	// if it's compressed, per RFC, it needs to start with either byte 0x02 or 0x03 (based on parity)
	if (len(seq) == constants.ECPLen && (seq[0] == 0x02 || seq[0] == 0x03)) ||
		// and if it's compressed it needs to start with 0x04 byte
		(len(seq) == constants.ECPLenUC && seq[0] == 0x04) {
		bind = Curve.ECP_fromBytes(seq)
	} else {
		// otherwise hash whatever we have onto a G1
		var err error
		bind, err = utils.HashBytesToG1(amcl.SHA256, seq)
		if err != nil {
			return nil, err
		}
	}
	return bind, nil
}

// ConstructTumblerProof constructs a zero knowledge proof required to
// implement Coconut's coin tumbler (https://arxiv.org/pdf/1802.07344.pdf).
// It proves knowledge of all private attributes in the credential and binds the proof to the address.
// Note that the first privM parameter HAS TO be coin's sequence number since the zeta is later revealed.
// loosely based on: https://github.com/asonnino/coconut-chainspace/blob/master/contracts/tumbler_proofs.py
// TODO: NEED SOMEBODY TO VERIFY CORECTNESS OF IMPLEMENTATION
// nolint: lll
func ConstructTumblerProof(params *Params, vk *VerificationKey, sig *Signature, privM []*Curve.BIG, t *Curve.BIG, address []byte) (*TumblerProof, error) {
	p, g1, g2, hs := params.p, params.g1, params.g2, params.hs

	// witnesses creation
	wm := GetRandomNums(params, len(privM))
	wt := GetRandomNums(params, 1)[0]

	// witnesses commitments
	Aw, Bw := constructKappaNuCommitments(vk, sig.sig1, wt, wm, privM)

	// privM[0] is the coin's sequence number
	Cw := Curve.G1mul(g1, wm[0]) // Cw = wm[0] * g1

	bind, err := CreateBinding(address)
	if err != nil {
		return nil, fmt.Errorf("Failed to bind to address: %v", err)
	}

	tmpSlice := []utils.Printable{g1, g2, vk.alpha, Aw, Bw, Cw, bind}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.beta))
	c, err := ConstructChallenge(ca)
	if err != nil {
		return nil, fmt.Errorf("Failed to construct challenge: %v", err)
	}

	// responses
	rm := CreateWitnessResponses(p, wm, c, privM)                            // rm[i] = (wm[i] - c * privM[i]) % o
	rt := CreateWitnessResponses(p, []*Curve.BIG{wt}, c, []*Curve.BIG{t})[0] // rt = (wt - c * t) % o

	zeta := Curve.G1mul(g1, privM[0])

	return &TumblerProof{
		baseProof: &VerifierProof{
			c:  c,
			rm: rm,
			rt: rt,
		},
		zeta: zeta,
	}, nil
}

// VerifyTumblerProof verifies non-interactive zero-knowledge proofs in order to check corectness of kappa, nu and zeta.
func VerifyTumblerProof(params *Params, vk *VerificationKey, sig *Signature, theta *ThetaTumbler, address []byte) bool {
	g1, g2, hs := params.g1, params.g2, params.hs

	Aw, Bw := reconstructKappaNuCommitments(params, vk, sig, theta.Theta)

	Cw := Curve.G1mul(g1, theta.proof.rm[0])
	Cw.Add(Curve.G1mul(theta.zeta, theta.proof.c))

	bind, err := CreateBinding(address)
	if err != nil {
		return false
	}

	tmpSlice := []utils.Printable{g1, g2, vk.alpha, Aw, Bw, Cw, bind}
	ca := utils.CombinePrintables(tmpSlice, utils.ECPSliceToPrintable(hs), utils.ECP2SliceToPrintable(vk.beta))
	c, err := ConstructChallenge(ca)
	if err != nil {
		return false
	}

	return Curve.Comp(theta.proof.c, c) == 0
}

// ShowBlindSignatureTumbler builds cryptographic material required for blind verification for the tumbler.
// It returns kappa, nu and zeta - group elements needed to perform verification
// and zero-knowledge proof asserting corectness of the above.
// The proof is bound to the provided address.
func ShowBlindSignatureTumbler(params *Params, vk *VerificationKey, sig *Signature, privM []*Curve.BIG, address []byte) (*ThetaTumbler, error) {
	p, rng := params.p, params.G.Rng()
	t := Curve.Randomnum(p, rng)

	kappa, nu, err := ConstructKappaNu(vk, sig, privM, t)
	if err != nil {
		return nil, err
	}

	tumblerProof, err := ConstructTumblerProof(params, vk, sig, privM, t, address)
	if err != nil {
		return nil, err
	}

	return &ThetaTumbler{
		Theta: &Theta{
			kappa: kappa,
			nu:    nu,
			proof: tumblerProof.baseProof,
		},
		zeta: tumblerProof.zeta,
	}, nil
}

// PairingWrapper basically performs what bpgroup.Pair does, however, it does not require the object.
// This is desirable as the function is called by Tendermint ABCI and bpgroup object is undetereministic due to rng.
func PairingWrapper(g1 *Curve.ECP, g2 *Curve.ECP2) *Curve.FP12 {
	return Curve.Fexp(Curve.Ate(g2, g1))
}

// BlindVerifyTumbler verifies the Coconut credential on the private and optional public attributes.
// It also checks the attached proof. It is designed to work for the tumbler system.
// nolint: lll
func BlindVerifyTumbler(params *Params, vk *VerificationKey, sig *Signature, theta *ThetaTumbler, pubM []*Curve.BIG, address []byte) bool {
	privateLen := len(theta.proof.rm)
	if len(pubM)+privateLen > len(vk.beta) || !VerifyTumblerProof(params, vk, sig, theta, address) {
		return false
	}

	if !sig.Validate() {
		return false
	}

	aggr := Curve.NewECP2() // new point is at infinity
	if len(pubM) > 0 {
		for i := 0; i < len(pubM); i++ {
			aggr.Add(Curve.G2mul(vk.beta[i+privateLen], pubM[i]))
		}
	}

	t1 := Curve.NewECP2()
	t1.Copy(theta.kappa)
	t1.Add(aggr)

	t2 := Curve.NewECP()
	t2.Copy(sig.sig2)
	t2.Add(theta.nu)

	Gt1 := PairingWrapper(sig.sig1, t1)
	Gt2 := PairingWrapper(t2, vk.g2)

	return !sig.sig1.Is_infinity() && Gt1.Equals(Gt2)
}
