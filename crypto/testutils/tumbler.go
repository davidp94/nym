// tumbler.go - Shared test functions for Coconut-tumbler implementations
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

// Package schemetest provides functions used for testing both regular and concurrent scheme.
package schemetest

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

// nolint: lll
func constructTumblerProofWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, vk *coconut.VerificationKey, sig *coconut.Signature, privM []*Curve.BIG, t *Curve.BIG, address []byte) (*coconut.TumblerProof, error) {
	if cw == nil {
		return coconut.ConstructTumblerProof(params.(*coconut.Params), vk, sig, privM, t, address)
	}
	return cw.ConstructTumblerProof(params.(*coconutworker.MuxParams), vk, sig, privM, t, address)
}

// nolint: lll
func verifyTumblerProofWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, vk *coconut.VerificationKey, sig *coconut.Signature, theta *coconut.ThetaTumbler, address []byte) bool {
	if cw == nil {
		return coconut.VerifyTumblerProof(params.(*coconut.Params), vk, sig, theta, address)
	}
	return cw.VerifyTumblerProof(params.(*coconutworker.MuxParams), vk, sig, theta, address)
}

// nolint: lll
func showBlindSignatureTumblerWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, vk *coconut.VerificationKey, sig *coconut.Signature, privM []*Curve.BIG, address []byte) (*coconut.ThetaTumbler, error) {
	if cw == nil {
		return coconut.ShowBlindSignatureTumbler(params.(*coconut.Params), vk, sig, privM, address)
	}
	return cw.ShowBlindSignatureTumbler(params.(*coconutworker.MuxParams), vk, sig, privM, address)
}

// nolint: lll
func blindVerifyTumblerWrapper(cw *coconutworker.CoconutWorker, params coconut.SchemeParams, vk *coconut.VerificationKey, sig *coconut.Signature, theta *coconut.ThetaTumbler, pubM []*Curve.BIG, address []byte) bool {
	if cw == nil {
		return coconut.BlindVerifyTumbler(params.(*coconut.Params), vk, sig, theta, pubM, address)
	}
	return cw.BlindVerifyTumbler(params.(*coconutworker.MuxParams), vk, sig, theta, pubM, address)
}

// TestTumblerProof tests properties of the appropriate NIZK
func TestTumblerProof(t *testing.T, cw *coconutworker.CoconutWorker) {
	tests := []struct {
		pub  []string
		priv []string
		msg  string
	}{
		{pub: []string{}, priv: []string{"Foo2"},
			msg: "The proof should verify on single private attribute"},
		{pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"},
			msg: "The proof should verify on three private attributes"},
		{pub: []string{"Foo"}, priv: []string{"Foo2"},
			msg: "The proof should verify on single public and private attributes"},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"},
			msg: "The proof should verify on three public and private attributes"},
	}

	for _, test := range tests {
		params, err := setupWrapper(cw, len(test.pub)+len(test.priv))
		assert.Nil(t, err)

		var G *bpgroup.BpGroup
		if cw == nil {
			G = params.(*coconut.Params).G
		} else {
			G = params.(*coconutworker.MuxParams).G
		}

		sk, vk, err := keygenWrapper(cw, params)
		assert.Nil(t, err)

		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))
		for i := range test.pub {
			pubBig[i], err = utils.HashStringToBig(amcl.SHA256, test.pub[i])
			assert.Nil(t, err)
		}
		for i := range test.priv {
			privBig[i], err = utils.HashStringToBig(amcl.SHA256, test.priv[i])
			assert.Nil(t, err)
		}

		egPriv, egPub := elGamalKeygenWrapper(cw, params)
		lambda, err := prepareBlindSignWrapper(cw, params, egPub, pubBig, privBig)
		assert.Nil(t, err)

		blindedSignature, err := blindSignWrapper(cw, params, sk, lambda, egPub, pubBig)
		assert.Nil(t, err)

		sig := unblindWrapper(cw, params, blindedSignature, egPriv)
		sig = randomizeWrapper(cw, params, sig)

		p, rng := params.P(), G.Rng()
		tr := Curve.Randomnum(p, rng)
		kappa, nu, err := coconut.ConstructKappaNu(vk, sig, privBig, tr)
		assert.Nil(t, err)

		r1 := Curve.Randomnum(p, rng)
		r2 := Curve.Randomnum(p, rng)

		ucecp := Curve.G1mul(params.G1(), r1)
		cecp := Curve.G1mul(params.G1(), r2)

		ucecpb := make([]byte, constants.ECPLenUC)
		cecpb := make([]byte, constants.ECPLen)

		ucecp.ToBytes(ucecpb, false)
		cecp.ToBytes(cecpb, true)

		addresses := [][]byte{
			nil,
			{1, 2, 3},
			ucecpb,
			cecpb,
		}

		for _, addr := range addresses {
			tp, err := constructTumblerProofWrapper(cw, params, vk, sig, privBig, tr, addr)
			if addr == nil {
				assert.Nil(t, tp)
				assert.Error(t, err)
				continue
			}

			theta := coconut.NewThetaTumbler(coconut.NewTheta(kappa, nu, tp.BaseProof()), tp.Zeta())

			assert.True(t, verifyTumblerProofWrapper(cw, params, vk, sig, theta, addr))
		}
	}
}

// TestBlindVerifyTumbler tests the blind verification of credentials used in a tumbler system
func TestBlindVerifyTumbler(t *testing.T, cw *coconutworker.CoconutWorker) {
	tests := []struct {
		q    int
		pub  []string
		priv []string
		err  error
	}{
		{q: 2, pub: []string{"Foo", "Bar"}, priv: []string{}, err: coconut.ErrPrepareBlindSignPrivate},
		{q: 1, pub: []string{}, priv: []string{"Foo", "Bar"}, err: coconut.ErrPrepareBlindSignParams},
		{q: 2, pub: []string{}, priv: []string{"Foo", "Bar"}, err: nil},
		{q: 6, pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}, err: nil},
		{q: 10, pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"}, err: nil},
	}

	for _, test := range tests {
		params, err := setupWrapper(cw, test.q)
		assert.Nil(t, err)

		sk, vk, err := keygenWrapper(cw, params)
		assert.Nil(t, err)
		egPriv, egPub := elGamalKeygenWrapper(cw, params)

		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))
		for i := range test.pub {
			pubBig[i], err = utils.HashStringToBig(amcl.SHA256, test.pub[i])
			assert.Nil(t, err)
		}
		for i := range test.priv {
			privBig[i], err = utils.HashStringToBig(amcl.SHA256, test.priv[i])
			assert.Nil(t, err)
		}

		lambda, err := prepareBlindSignWrapper(cw, params, egPub, pubBig, privBig)

		if len(test.priv) == 0 {
			assert.Equal(t, test.err, err)
			continue
		} else if test.q < len(test.priv)+len(test.pub) {
			assert.Equal(t, test.err, err)
			continue
		} else {
			assert.Nil(t, err)
		}

		// ensures len(lambda.enc)+len(public_m) > len(params.hs)
		if test.q <= len(test.priv)+len(test.pub) {
			_, err = blindSignWrapper(cw, params, sk, lambda, egPub, append(pubBig, Curve.NewBIG()))
			assert.Equal(t, coconut.ErrPrepareBlindSignParams, err)

			// just to ensure the error is returned; proofs of knowledge are properly tested in their own test file
			_, err = blindSignWrapper(cw, params, sk, lambda, egPub, append(pubBig, Curve.NewBIG()))
			assert.Equal(t, coconut.ErrPrepareBlindSignParams, err)
		}

		blindedSignature, err := blindSignWrapper(cw, params, sk, lambda, egPub, pubBig)
		assert.Nil(t, err)
		sig := unblindWrapper(cw, params, blindedSignature, egPriv)

		p := params.P()
		bp := bpgroup.New()
		rng := bp.Rng()

		r1 := Curve.Randomnum(p, rng)
		r2 := Curve.Randomnum(p, rng)

		ucecp := Curve.G1mul(params.G1(), r1)
		cecp := Curve.G1mul(params.G1(), r2)

		ucecpb := make([]byte, constants.ECPLenUC)
		cecpb := make([]byte, constants.ECPLen)

		ucecp.ToBytes(ucecpb, false)
		cecp.ToBytes(cecpb, true)

		addresses := [][]byte{
			nil,
			{1, 2, 3},
			ucecpb,
			cecpb,
		}

		for _, addr := range addresses {
			_, err = showBlindSignatureTumblerWrapper(cw, params, vk, sig, []*Curve.BIG{}, addr)
			assert.Equal(t, coconut.ErrShowBlindAttr, err)

			if len(test.pub) == 0 {
				// ensures len(private_m) > len(vk.beta)
				_, err = showBlindSignatureTumblerWrapper(cw, params, vk, sig, append(privBig, Curve.NewBIG()), addr)
				assert.Equal(t, coconut.ErrShowBlindAttr, err)
			}

			thetaTumbler, err := showBlindSignatureTumblerWrapper(cw, params, vk, sig, privBig, addr)

			if addr == nil {
				assert.Nil(t, thetaTumbler)
				assert.Error(t, err)
				continue
			}

			assert.NotNil(t, thetaTumbler)
			assert.Nil(t, err)

			assert.True(t, blindVerifyTumblerWrapper(cw, params, vk, sig, thetaTumbler, pubBig, addr))
			// private attributes are revealed
			assert.True(t, verifyWrapper(cw, params, vk, append(privBig, pubBig...), sig))

		}
	}
}
