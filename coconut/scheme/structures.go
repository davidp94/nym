// structures.go - Data structures for coconut signature scheme
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
	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/elgamal"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// SecretKey represents secret key of a Coconut signing authority.
type SecretKey struct {
	x *Curve.BIG
	y []*Curve.BIG
}

// X returns appropriate part of the the secret key
func (sk *SecretKey) X() *Curve.BIG {
	return sk.x
}

// Y returns appropriate part of the the secret key
func (sk *SecretKey) Y() []*Curve.BIG {
	return sk.y
}

// VerificationKey represents verification key of a Coconut signing authority.
type VerificationKey struct {
	g2    *Curve.ECP2
	alpha *Curve.ECP2
	beta  []*Curve.ECP2
}

// G2 returns generator of G2 that is part of the verification key
func (vk *VerificationKey) G2() *Curve.ECP2 {
	return vk.g2
}

// Alpha returns appropriate part of the the verification key
func (vk *VerificationKey) Alpha() *Curve.ECP2 {
	return vk.alpha
}

// Beta returns appropriate part of the the verification key
func (vk *VerificationKey) Beta() []*Curve.ECP2 {
	return vk.beta
}

// Signature represents signature/credential issued by a Coconut signing authority.
// sig1 = h,
// sig2 = h * (x + (m[0] * y[0]) + ... + (m[i] * y[i])).
type Signature struct {
	sig1 *Curve.ECP
	sig2 *Curve.ECP
}

// Sig1 returns first ECP group of the signature
func (s *Signature) Sig1() *Curve.ECP {
	return s.sig1
}

// Sig2 returns second ECP group of the signature
func (s *Signature) Sig2() *Curve.ECP {
	return s.sig2
}

// BlindedSignature represents blinded version of a normal Coconut signature
type BlindedSignature struct {
	sig1      *Curve.ECP
	sig2Tilda *elgamal.Encryption
}

// SchemeParams interface allows for interchangeably using Params and MuxParams
// (where applicable)
type SchemeParams interface {
	P() *Curve.BIG
	G1() *Curve.ECP
	G2() *Curve.ECP2
	Hs() []*Curve.ECP
}

// Params represent public system-wide parameters.
type Params struct {
	G  *bpgroup.BpGroup // represents G1, G2, GT
	p  *Curve.BIG
	g1 *Curve.ECP
	g2 *Curve.ECP2
	hs []*Curve.ECP
}

// P returns order of the group in params
func (p *Params) P() *Curve.BIG {
	return p.p
}

// G1 returns generator of G1 in params
func (p *Params) G1() *Curve.ECP {
	return p.g1
}

// G2 returns generator of G2 in params
func (p *Params) G2() *Curve.ECP2 {
	return p.g2
}

// Hs returns generators of G1 in params
func (p *Params) Hs() []*Curve.ECP {
	return p.hs
}

// BlindSignMats encapsulates data created by PrepareBlindSign function.
type BlindSignMats struct {
	cm    *Curve.ECP
	enc   []*elgamal.Encryption
	proof *SignerProof
}

// Cm returns the commitment part of the BlindSignMats
func (bsm *BlindSignMats) Cm() *Curve.ECP {
	return bsm.cm
}

// Enc returns the encryptions part of the BlindSignMats
func (bsm *BlindSignMats) Enc() []*elgamal.Encryption {
	return bsm.enc
}

// Proof returns the proof part of the BlindSignMats
func (bsm *BlindSignMats) Proof() *SignerProof {
	return bsm.proof
}

// BlindShowMats encapsulates data created by ShowBlindSignature function.
type BlindShowMats struct {
	kappa *Curve.ECP2
	nu    *Curve.ECP
	proof *VerifierProof
}

// Kappa returns the kappa part of the BlindShowMats
func (bsm *BlindShowMats) Kappa() *Curve.ECP2 {
	return bsm.kappa
}

// Nu returns the nu part of the BlindShowMats
func (bsm *BlindShowMats) Nu() *Curve.ECP {
	return bsm.nu
}

// Proof returns the proof part of the BlindShowMats
func (bsm *BlindShowMats) Proof() *VerifierProof {
	return bsm.proof
}

// PolynomialPoints (tmp) represents x values of points on polynomial of degree t - 1
// generated during TTPKeygen.
type PolynomialPoints struct {
	xs []*Curve.BIG
}

// Xs returns slice of x coordinates of Polynomial Points
func (pp *PolynomialPoints) Xs() []*Curve.BIG {
	return pp.xs
}

// SignerProof (name to be confirmed) represents all the fields contained within the said proof.
type SignerProof struct {
	c  *Curve.BIG
	rr *Curve.BIG
	rk []*Curve.BIG
	rm []*Curve.BIG
}

// C returns challenge part of the signer proof
func (sp *SignerProof) C() *Curve.BIG {
	return sp.c
}

// Rr returns set of rr responses of the signer proof
func (sp *SignerProof) Rr() *Curve.BIG {
	return sp.rr
}

// Rk returns set of rk responses of the signer proof
func (sp *SignerProof) Rk() []*Curve.BIG {
	return sp.rk
}

// Rm returns set of rm responses of the signer proof
func (sp *SignerProof) Rm() []*Curve.BIG {
	return sp.rm
}

// VerifierProof (name to be confirmed) represents all the fields contained within the said proof.
type VerifierProof struct {
	c  *Curve.BIG
	rm []*Curve.BIG
	rt *Curve.BIG
}

// C returns challenge part of the signer proof
func (vp *VerifierProof) C() *Curve.BIG {
	return vp.c
}

// Rm returns set of rm responses of the signer proof
func (vp *VerifierProof) Rm() []*Curve.BIG {
	return vp.rm
}

// Rt returns set of rt responses of the signer proof
func (vp *VerifierProof) Rt() *Curve.BIG {
	return vp.rt
}

// NewSk returns instance of verification key from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewSk(x *Curve.BIG, y []*Curve.BIG) *SecretKey {
	return &SecretKey{
		x: x,
		y: y,
	}
}

// NewVk returns instance of verification key from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewVk(g2 *Curve.ECP2, alpha *Curve.ECP2, beta []*Curve.ECP2) *VerificationKey {
	return &VerificationKey{
		g2:    g2,
		alpha: alpha,
		beta:  beta,
	}
}

// NewSignature returns instance of signature from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewSignature(sig1 *Curve.ECP, sig2 *Curve.ECP) *Signature {
	return &Signature{
		sig1: sig1,
		sig2: sig2,
	}
}

// NewPP returns instance of PolynomialPoints from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewPP(xs []*Curve.BIG) *PolynomialPoints {
	return &PolynomialPoints{
		xs: xs,
	}
}

// NewBlindSignMats returns instance of BlindSignMats from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewBlindSignMats(cm *Curve.ECP, enc []*elgamal.Encryption, proof *SignerProof) *BlindSignMats {
	return &BlindSignMats{
		cm:    cm,
		enc:   enc,
		proof: proof,
	}
}

// NewBlindShowMats returns instance of BlindShowMats from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewBlindShowMats(kappa *Curve.ECP2, nu *Curve.ECP, proof *VerifierProof) *BlindShowMats {
	return &BlindShowMats{
		kappa: kappa,
		nu:    nu,
		proof: proof,
	}
}

// NewSignerProof returns instance of SignerProof from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewSignerProof(c *Curve.BIG, rr *Curve.BIG, rk []*Curve.BIG, rm []*Curve.BIG) *SignerProof {
	return &SignerProof{
		c:  c,
		rr: rr,
		rk: rk,
		rm: rm,
	}
}

// NewVerifierProof returns instance of VerifierProof from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewVerifierProof(c *Curve.BIG, rm []*Curve.BIG, rt *Curve.BIG) *VerifierProof {
	return &VerifierProof{
		c:  c,
		rm: rm,
		rt: rt,
	}
}

// NewBlindedSignature returns instance of BlindedSignature from the provided attributes.
// Created for coconutclientworker to not repeat the type definition but preserve attributes being private.
func NewBlindedSignature(sig1 *Curve.ECP, sig2Tilda *elgamal.Encryption) *BlindedSignature {
	return &BlindedSignature{
		sig1:      sig1,
		sig2Tilda: sig2Tilda,
	}
}
