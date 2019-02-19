// coconut_worker.go - Coconut server listener.
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

// Package coconutworker is a wrapper for computing coconut-related operations concurrently,
// such that the callee does not need to be concerned with system-wide params.
package coconutworker

import (
	"sync"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// CoconutWorker allows writing coconut actions to a shared job queue,
// so that they could be run concurrently.
type CoconutWorker struct {
	jobQueue  chan<- *jobpacket.JobPacket
	muxParams *MuxParams
}

// SignWrapper wraps the provided arguments with pre-generated params.
func (cw *CoconutWorker) SignWrapper(sk *coconut.SecretKey, pubM []*Curve.BIG) (*coconut.Signature, error) {
	return cw.Sign(cw.muxParams, sk, pubM)
}

// BlindSignWrapper wraps the provided arguments with pre-generated params.
// nolint: lll
func (cw *CoconutWorker) BlindSignWrapper(sk *coconut.SecretKey, l *coconut.Lambda, egPub *elgamal.PublicKey, pubM []*Curve.BIG) (*coconut.BlindedSignature, error) {
	return cw.BlindSign(cw.muxParams, sk, l, egPub, pubM)
}

// VerifyWrapper wraps the provided arguments with pre-generated params.
func (cw *CoconutWorker) VerifyWrapper(vk *coconut.VerificationKey, pubM []*Curve.BIG, sig *coconut.Signature) bool {
	return cw.Verify(cw.muxParams, vk, pubM, sig)
}

// BlindVerifyWrapper wraps the provided arguments with pre-generated params.
// nolint: lll
func (cw *CoconutWorker) BlindVerifyWrapper(vk *coconut.VerificationKey, sig *coconut.Signature, t *coconut.Theta, pubM []*Curve.BIG) bool {
	return cw.BlindVerify(cw.muxParams, vk, sig, t, pubM)
}

// AggregateVerificationKeysWrapper wraps the provided arguments with pre-generated params.
// nolint: lll
func (cw *CoconutWorker) AggregateVerificationKeysWrapper(vks []*coconut.VerificationKey, pp *coconut.PolynomialPoints) *coconut.VerificationKey {
	return cw.AggregateVerificationKeys(cw.muxParams, vks, pp)
}

// AggregateSignaturesWrapper wraps the provided arguments with pre-generated params.
// nolint: lll
func (cw *CoconutWorker) AggregateSignaturesWrapper(sigs []*coconut.Signature, pp *coconut.PolynomialPoints) *coconut.Signature {
	return cw.AggregateSignatures(cw.muxParams, sigs, pp)
}

// UnblindWrapper wraps the provided arguments with pre-generated params.
// nolint: lll
func (cw *CoconutWorker) UnblindWrapper(blindedSignature *coconut.BlindedSignature, egPub *elgamal.PrivateKey) *coconut.Signature {
	return cw.Unblind(cw.muxParams, blindedSignature, egPub)
}

// RandomizeWrapper wraps the provided arguments with pre-generated params.
func (cw *CoconutWorker) RandomizeWrapper(sig *coconut.Signature) *coconut.Signature {
	return cw.Randomize(cw.muxParams, sig)
}

// PrepareBlindSignWrapper wraps the provided arguments with pre-generated params.
// nolint: lll
func (cw *CoconutWorker) PrepareBlindSignWrapper(egPub *elgamal.PublicKey, pubM []*Curve.BIG, privM []*Curve.BIG) (*coconut.Lambda, error) {
	return cw.PrepareBlindSign(cw.muxParams, egPub, pubM, privM)
}

// ShowBlindSignatureWrapper wraps the provided arguments with pre-generated params.
// nolint: lll
func (cw *CoconutWorker) ShowBlindSignatureWrapper(vk *coconut.VerificationKey, sig *coconut.Signature, privM []*Curve.BIG) (*coconut.Theta, error) {
	return cw.ShowBlindSignature(cw.muxParams, vk, sig, privM)
}

// PrepareBlindSignTokenWrapper wraps the provided arguments with pre-generated params
// and unwraps attributes embedded in the token.
// nolint: lll
func (cw *CoconutWorker) PrepareBlindSignTokenWrapper(egPub *elgamal.PublicKey, token *token.Token) (*coconut.Lambda, error) {
	pubM, privM := token.GetPublicAndPrivateSlices()
	return cw.PrepareBlindSign(cw.muxParams, egPub, pubM, privM)
}

// New creates new instance of a coconutWorker.
func New(jobQueue chan<- *jobpacket.JobPacket, params *coconut.Params) *CoconutWorker {
	muxParams := &MuxParams{params, sync.Mutex{}}
	cw := &CoconutWorker{
		jobQueue:  jobQueue,
		muxParams: muxParams,
	}

	return cw
}
