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

	"github.com/jstuczyn/CoconutGo/crypto/elgamal"

	"github.com/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/utils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

var (
	ErrMarshalMethod       = errors.New("Can't marshal this structure")
	ErrMarshalTooLongArray = errors.New("The array is the struct has more than 255 elements")
	ErrMarshalBSMArray     = errors.New("There are more than 15/23 private attributes")
)

// todo: marshal/unmarshal params?

// getBaseFromAttributes generates the base h from public attributes.
// It is only used for Sign function that works exlusively on public attributes
// todo: actually logic in code is identical to constructChallenge in proofs
// (apart from SHA used) - combine them?
func getBaseFromAttributes(pubM []*Curve.BIG) *Curve.ECP {
	s := make([]string, len(pubM))
	for i := range pubM {
		s[i] = utils.ToCoconutString(pubM[i])
	}
	h, err := utils.HashStringToG1(amcl.SHA512, strings.Join(s, ","))
	if err != nil {
		panic(err)
	}
	return h
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (vr VerificationResult) MarshalBinary() ([]byte, error) {
	if vr {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sk *SecretKey) MarshalBinary() ([]byte, error) {
	blen := constants.BIGLen
	// sk consists of len(ys) + 1 values which are all of same, constant, length
	data := make([]byte, blen*(len(sk.y)+1))
	sk.x.ToBytes(data)
	for i := range sk.y {
		sk.y[i].ToBytes(data[blen*(i+1):])
	}
	return data, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sk *SecretKey) UnmarshalBinary(data []byte) error {
	blen := constants.BIGLen
	if len(data)%blen != 0 || len(data) < 2*blen {
		return constants.ErrUnmarshalLength
	}
	x := Curve.FromBytes(data)
	y := make([]*Curve.BIG, (len(data)/blen - 1))
	for i := range y {
		y[i] = Curve.FromBytes(data[blen*(i+1):])
	}
	sk.x = x
	sk.y = y
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (vk *VerificationKey) MarshalBinary() ([]byte, error) {
	ec2len := constants.ECP2Len
	// sk consists of len(beta) + 2 values which are all of same, constant, length
	data := make([]byte, (ec2len * (len(vk.beta) + 2)))
	vk.g2.ToBytes(data)
	vk.alpha.ToBytes(data[ec2len:])
	for i := range vk.beta {
		vk.beta[i].ToBytes(data[ec2len*(i+2):])
	}
	return data, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (vk *VerificationKey) UnmarshalBinary(data []byte) error {
	ec2len := constants.ECP2Len

	if len(data)%ec2len != 0 || len(data) < 3*ec2len {
		return constants.ErrUnmarshalLength
	}
	g2 := Curve.ECP2_fromBytes(data)
	alpha := Curve.ECP2_fromBytes(data[ec2len:])
	beta := make([]*Curve.ECP2, (len(data)/ec2len - 2))
	for i := range beta {
		beta[i] = Curve.ECP2_fromBytes(data[ec2len*(i+2):])
	}
	vk.g2 = g2
	vk.alpha = alpha
	vk.beta = beta
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sig *Signature) MarshalBinary() ([]byte, error) {
	eclen := constants.ECPLen
	data := make([]byte, eclen*2)
	sig.sig1.ToBytes(data, true)
	sig.sig2.ToBytes(data[eclen:], true)
	return data, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sig *Signature) UnmarshalBinary(data []byte) error {
	eclen := constants.ECPLen
	if len(data) != 2*eclen {
		return constants.ErrUnmarshalLength
	}
	sig1 := Curve.ECP_fromBytes(data)
	sig2 := Curve.ECP_fromBytes(data[eclen:])
	sig.sig1 = sig1
	sig.sig2 = sig2
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (bs *BlindedSignature) MarshalBinary() ([]byte, error) {
	eclen := constants.ECPLen

	data := make([]byte, eclen*3)
	bs.sig1.ToBytes(data, true)
	sig2data, err := bs.sig2Tilda.MarshalBinary()
	if err != nil || len(sig2data) != 2*eclen {
		return nil, err
	}
	copy(data[eclen:], sig2data)
	return data, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (bs *BlindedSignature) UnmarshalBinary(data []byte) error {
	eclen := constants.ECPLen

	if len(data) != 3*eclen {
		return constants.ErrUnmarshalLength
	}
	sig1 := Curve.ECP_fromBytes(data)
	sig2Tilda := &elgamal.Encryption{}
	sig2Tilda.UnmarshalBinary(data[eclen:])
	bs.sig1 = sig1
	bs.sig2Tilda = sig2Tilda
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sp *SignerProof) MarshalBinary() ([]byte, error) {
	blen := constants.BIGLen
	if !constants.MarshalEmbedHelperData {
		// without embedding array sizes, it is impossible (or at least I could not figure it out)
		// how to distinguish two arrays so that they could be unmarshaled later
		return nil, ErrMarshalMethod
	}
	data := make([]byte, blen*(2+len(sp.rk)+len(sp.rm))+1)
	sp.c.ToBytes(data)
	sp.rr.ToBytes(data[blen:])
	// realistically it should never, ever fail, because it would imply credential
	// has more than 255 private attributes...
	if len(sp.rk) > 255 {
		return nil, ErrMarshalTooLongArray
	}
	data[2*blen] = byte(len(sp.rk)) // due to previous check guaranteed to be less than 255
	for i := range sp.rk {
		// sp.rk[i].ToBytes(data[(2*blen+1)+blen*i:])
		sp.rk[i].ToBytes(data[blen*(2+i)+1:])
	}
	// we do not need to put the size of the other array since it can be implied for the length of data packet
	for i := range sp.rm {
		// sp.rm[i].ToBytes(data[(2*blen+1+blen*len(sp.rk))+blen*i:])
		sp.rm[i].ToBytes(data[blen*(2+len(sp.rk)+i)+1:])
	}
	return data, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sp *SignerProof) UnmarshalBinary(data []byte) error {
	if !constants.MarshalEmbedHelperData {
		// same reasoning as above
		return ErrMarshalMethod
	}

	blen := constants.BIGLen

	if (len(data)-1)%blen != 0 || len(data) < 3*blen+1 {
		return constants.ErrUnmarshalLength
	}

	c := Curve.FromBytes(data)
	rr := Curve.FromBytes(data[blen:])
	rkLen := int(data[2*blen])
	rk := make([]*Curve.BIG, rkLen)
	for i := range rk {
		rk[i] = Curve.FromBytes(data[blen*(2+i)+1:])
	}

	rmLenBytes := len(data[blen*(2+rkLen)+1:])
	// just a sanity check. Realistically it should never, ever happen
	if rmLenBytes%blen != 0 {
		return constants.ErrUnmarshalLength
	}
	rmLen := rmLenBytes / blen
	rm := make([]*Curve.BIG, rmLen)
	for i := range rm {
		rm[i] = Curve.FromBytes(data[blen*(2+rkLen+i)+1:])
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
	blen := constants.BIGLen
	eclen := constants.ECPLen

	// it depends here if we really care about the 'overhead' (and hence possible compatibility) of 2 bytes
	// vs slightly more complicated implementation and limitation of maximum of number of attributes (15 for BN, 23 for BLS; basically MB/2-1)
	if constants.MarshalEmbedHelperData {
		data := make([]byte, eclen*(1+2*len(bsm.enc))+blen*(2+len(bsm.proof.rk)+len(bsm.proof.rm))+2)
		bsm.cm.ToBytes(data, true)
		if len(bsm.enc) > 255 {
			return nil, ErrMarshalTooLongArray
		}

		data[eclen] = byte(len(bsm.enc))
		for i := range bsm.enc {
			enciData, err := bsm.enc[i].MarshalBinary()
			if err != nil || len(enciData) != 2*eclen {
				return nil, err
			}
			copy(data[1+eclen*(1+2*i):], enciData)
		}
		proofdata, err := bsm.proof.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[1+eclen*(1+2*len(bsm.enc)):], proofdata)
		return data, nil

	} else {
		if len(bsm.enc) > constants.MB/2-1 {
			return nil, ErrMarshalBSMArray
		}
		// we need to manually embbed the proof here since it is impossible to infer all its attributes on their own
		// Cm || enc[0].c1 || enc[0].c2 || ... || rr || rk[0] || ... || rm[0] || ...
		data := make([]byte, eclen*(1+2*len(bsm.enc))+blen*(2+len(bsm.proof.rk)+len(bsm.proof.rm)))
		bsm.cm.ToBytes(data, true)
		for i := range bsm.enc {
			enciData, err := bsm.enc[i].MarshalBinary()
			if err != nil || len(enciData) != 2*eclen {
				return nil, err
			}
			copy(data[eclen*(1+2*i):], enciData)
		}

		// doing proof here rather than calling marshal on it as it is an invalid operation to marshal the proof on itself without embeding array lenghts

		// reference to further in the data array for easier and more readable operations
		proofdata := data[eclen*(1+2*len(bsm.enc)):]

		bsm.proof.c.ToBytes(proofdata)
		bsm.proof.rr.ToBytes(proofdata[blen:])

		for i := range bsm.proof.rk {
			bsm.proof.rk[i].ToBytes(proofdata[blen*(2+i):])
		}
		for i := range bsm.proof.rm {
			bsm.proof.rm[i].ToBytes(proofdata[blen*(2+len(bsm.proof.rk)+i):])
		}

		return data, nil
	}
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (bsm *BlindSignMats) UnmarshalBinary(data []byte) error {
	blen := constants.BIGLen
	eclen := constants.ECPLen

	if constants.MarshalEmbedHelperData {
		cm := Curve.ECP_fromBytes(data)
		numEnc := int(data[eclen])
		enc := make([]*elgamal.Encryption, numEnc)
		for i := range enc {
			enc[i] = &elgamal.Encryption{}
			err := enc[i].UnmarshalBinary(data[1+eclen*(1+i*2):])
			if err != nil {
				return err
			}
		}
		proof := &SignerProof{}
		err := proof.UnmarshalBinary(data[1+eclen*(1+2*numEnc):])
		if err != nil {
			return err
		}
		bsm.cm = cm
		bsm.enc = enc
		bsm.proof = proof
		return nil

	} else {
		// corectness of unmarshaling with the method depends on the below
		if eclen != blen+1 {
			return errors.New("Eclen != blen + 1 - something is terribly wrong. Changed implementation?")
		}
		cm := Curve.ECP_fromBytes(data)

		numEnc := (len(data)%blen - 1) / 2
		enc := make([]*elgamal.Encryption, numEnc)
		for i := range enc {
			enc[i] = &elgamal.Encryption{}
			err := enc[i].UnmarshalBinary(data[eclen*(1+i*2):])
			if err != nil {
				return err
			}
		}
		// reference to further in the data array for easier and more readable operations
		proofdata := data[eclen*(1+2*numEnc):]

		c := Curve.FromBytes(proofdata)
		rr := Curve.FromBytes(proofdata[blen:])

		// number of rk is the same as number of enc as both of them correspond to single private attribute
		rk := make([]*Curve.BIG, numEnc)
		for i := range rk {
			rk[i] = Curve.FromBytes(proofdata[blen*(2+i):])
		}

		// the remaining bytes are used for rm
		rmLenBytes := len(proofdata[blen*(2+numEnc):])
		// just a sanity check. Realistically it should never, ever happen
		if rmLenBytes%blen != 0 {
			return constants.ErrUnmarshalLength
		}
		rmLen := rmLenBytes / blen
		rm := make([]*Curve.BIG, rmLen)

		for i := range rm {
			rm[i] = Curve.FromBytes(proofdata[blen*(2+numEnc+i):])
		}

		proof := NewSignerProof(c, rr, rk, rm)
		bsm.cm = cm
		bsm.enc = enc
		bsm.proof = proof
		return nil
	}
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (vp *VerifierProof) MarshalBinary() ([]byte, error) {
	blen := constants.BIGLen
	data := make([]byte, blen*(2+len(vp.rm)))
	vp.c.ToBytes(data)
	vp.rt.ToBytes(data[blen:])
	for i := range vp.rm {
		vp.rm[i].ToBytes(data[blen*(2+i):])
	}
	return data, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (vp *VerifierProof) UnmarshalBinary(data []byte) error {
	blen := constants.BIGLen
	if len(data)%blen != 0 || len(data) < 3*blen {
		return constants.ErrUnmarshalLength
	}
	c := Curve.FromBytes(data)
	rt := Curve.FromBytes(data[blen:])

	rmLenBytes := len(data[2*blen:])
	// just a sanity check. Realistically it should never, ever happen
	if rmLenBytes%blen != 0 {
		return constants.ErrUnmarshalLength
	}
	rmLen := rmLenBytes / blen
	rm := make([]*Curve.BIG, rmLen)
	for i := range rm {
		rm[i] = Curve.FromBytes(data[blen*(2+i):])
	}
	vp.c = c
	vp.rt = rt
	vp.rm = rm
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (bsm *BlindShowMats) MarshalBinary() ([]byte, error) {
	blen := constants.BIGLen
	eclen := constants.ECPLen
	ec2len := constants.ECP2Len

	data := make([]byte, ec2len+eclen+blen*(2+len(bsm.proof.rm)))
	bsm.kappa.ToBytes(data)
	bsm.nu.ToBytes(data[ec2len:], true)
	proofdata, err := bsm.proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[ec2len+eclen:], proofdata)

	return data, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (bsm *BlindShowMats) UnmarshalBinary(data []byte) error {
	eclen := constants.ECPLen
	ec2len := constants.ECP2Len

	kappa := Curve.ECP2_fromBytes(data)
	nu := Curve.ECP_fromBytes(data[ec2len:])
	proof := &VerifierProof{}
	err := proof.UnmarshalBinary(data[ec2len+eclen:])
	if err != nil {
		return err
	}

	bsm.kappa = kappa
	bsm.nu = nu
	bsm.proof = proof

	return nil
}
