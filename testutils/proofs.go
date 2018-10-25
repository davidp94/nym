// proofs.go - Shared test functions for Coconut implementations
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

// Package schemetest provides functions used for testing both regular and concurrent coconut scheme.
package schemetest

import (
	"testing"

	"github.com/jstuczyn/CoconutGo/bpgroup"

	"github.com/jstuczyn/CoconutGo/coconut/scheme"

	"github.com/jstuczyn/CoconutGo/coconut/concurrency/coconutclient"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/CoconutGo/elgamal"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func constructSignerProofWrapper(ccw *coconutclient.Worker, params coconut.CoconutParams, gamma *Curve.ECP, encs []*elgamal.Encryption, cm *Curve.ECP, k []*Curve.BIG, r *Curve.BIG, pubM []*Curve.BIG, privM []*Curve.BIG) (*coconut.SignerProof, error) {
	if ccw == nil {
		return coconut.ConstructSignerProof(params.(*coconut.Params), gamma, encs, cm, k, r, pubM, privM)
	}
	return ccw.ConstructSignerProof(params.(*coconutclient.MuxParams), gamma, encs, cm, k, r, pubM, privM)
}

func verifySignerProofWrapper(ccw *coconutclient.Worker, params coconut.CoconutParams, gamma *Curve.ECP, encs []*elgamal.Encryption, cm *Curve.ECP, proof *coconut.SignerProof) bool {
	if ccw == nil {
		return coconut.VerifySignerProof(params.(*coconut.Params), gamma, encs, cm, proof)
	}
	return ccw.VerifySignerProof(params.(*coconutclient.MuxParams), gamma, encs, cm, proof)
}

// TestSignerProof tests properties of the appropriate NIZK
func TestSignerProof(t *testing.T, ccw *coconutclient.Worker) {
	tests := []struct {
		pub  []string
		priv []string
		msg  string
	}{
		{pub: []string{}, priv: []string{"Foo2"}, msg: "The proof should verify on single private attribute"},
		{pub: []string{}, priv: []string{"Foo2", "Bar2", "Baz2"}, msg: "The proof should verify on three private attributes"},
		{pub: []string{"Foo"}, priv: []string{}, msg: "The proof should verify on single public attribute"},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{}, msg: "The proof should verify on three public attribute"},
		{pub: []string{"Foo"}, priv: []string{"Foo2"},
			msg: "The proof should verify on single public and private attributes"},
		{pub: []string{"Foo", "Bar", "Baz"}, priv: []string{"Foo2", "Bar2", "Baz2"},
			msg: "The proof should verify on three public and private attributes"},
	}

	for _, test := range tests {
		params, _, _ := setupAndKeygen(t, len(test.pub)+len(test.priv), ccw)
		var G *bpgroup.BpGroup
		if ccw == nil {
			G = params.(*coconut.Params).G
		} else {
			G = params.(*coconutclient.MuxParams).G
		}
		p, g1, hs, rng := params.P(), params.G1(), params.Hs(), G.Rng()

		pubBig := make([]*Curve.BIG, len(test.pub))
		privBig := make([]*Curve.BIG, len(test.priv))
		var err error
		for i := range test.pub {
			pubBig[i], err = utils.HashStringToBig(amcl.SHA256, test.pub[i])
			assert.Nil(t, err)
		}
		for i := range test.priv {
			privBig[i], err = utils.HashStringToBig(amcl.SHA256, test.priv[i])
			assert.Nil(t, err)
		}

		attributes := append(privBig, pubBig...)

		// even if executed in parallel, no need to lock as an unique instance of Rng was created for the test
		r := Curve.Randomnum(p, rng)
		cm := Curve.G1mul(g1, r)
		for i := range attributes {
			cm.Add(Curve.G1mul(hs[i], attributes[i]))
		}

		b := make([]byte, utils.MB+1)
		cm.ToBytes(b, true)

		h, err := utils.HashBytesToG1(amcl.SHA512, b)
		assert.Nil(t, err)

		var gamma *Curve.ECP
		if ccw == nil {
			_, gamma = elgamal.Keygen(params.(*coconut.Params).G)
		} else {
			_, gamma = ccw.ElGamalKeygen(params.(*coconutclient.MuxParams))
		}

		encs := make([]*elgamal.Encryption, len(test.priv))
		ks := make([]*Curve.BIG, len(test.priv))
		for i := range test.priv {
			c, k := elgamal.Encrypt(G, gamma, privBig[i], h)
			encs[i] = c
			ks[i] = k
		}

		if len(test.priv) > 0 {
			_, err = constructSignerProofWrapper(ccw, params, gamma, encs, cm, ks[1:], r, pubBig, privBig)
			assert.Equal(t, coconut.ErrConstructSignerCiphertexts, err)

			_, err = constructSignerProofWrapper(ccw, params, gamma, encs[1:], cm, ks, r, pubBig, privBig)
			assert.Equal(t, coconut.ErrConstructSignerCiphertexts, err)

			_, err = constructSignerProofWrapper(ccw, params, gamma, encs, cm, ks, r, pubBig, privBig[1:])
			assert.Equal(t, coconut.ErrConstructSignerCiphertexts, err)
		}

		_, err = constructSignerProofWrapper(ccw, params, gamma, encs, cm, ks, r, append(pubBig, Curve.NewBIG()), privBig)
		assert.Equal(t, coconut.ErrConstructSignerAttrs, err)

		signerProof, err := constructSignerProofWrapper(ccw, params, gamma, encs, cm, ks, r, pubBig, privBig)
		assert.Nil(t, err)

		if len(test.priv) > 0 {
			assert.False(t, verifySignerProofWrapper(ccw, params, gamma, encs[1:], cm, signerProof), test.msg)
			assert.False(t, verifySignerProofWrapper(ccw, params, gamma, encs, cm,
				coconut.NewSignerProof(signerProof.C(), signerProof.Rr(), signerProof.Rk()[1:], signerProof.Rm())),
				test.msg)
		}
		assert.True(t, verifySignerProofWrapper(ccw, params, gamma, encs, cm, signerProof), test.msg)
	}

}
