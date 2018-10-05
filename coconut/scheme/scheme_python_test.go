// scheme_python_test.go - tests compatibility with Python implementation
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
package coconut

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
	_ "github.com/jstuczyn/CoconutGo/elgamal"
	_ "github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BN254"
)

func TestCompareWithPython(t *testing.T) {
	g1Hex := "032523648240000001ba344d80000000086121000000000013a700000000000012"
	g2Hex := "061a10bb519eb62feb8d8c7e8c61edb6a4648bbb4898bf0d91ee4224c803fb2b0516aaf9ba737833310aa78c5982aa5b1f4d746bae3784b70d8c34c1e7d54cf3021897a06baf93439a90e096698c822329bd0ae6bdbe09bd19f0e07891cd2b9a0ebb2b0e7c8b15268f6d4456f5f38d37b09006ffd739c9578a2d1aec6b3ace9b"
	ordHex := "2523648240000001BA344D8000000007FF9F800000000010A10000000000000D"
	xHex := "076501B5E73FA81B28FAB06EE3F6929E6AE4DB9461A49930C49EF1B28A625DD2"
	y0Hex := "0CE30F26C29ADBE06AE98D9B49DB3FF323C8100072298E9A58AC347E9BE59F36"
	mHex := "1D70206E93922A266B6F522CB1EC8AA72F908AC87EED1E43C641BFAF3C82AC32"
	g1resHex := "02096d26612159d5339748b78c53000734df70a678f4d2ce389b422b076bf5996b"
	XHex := "13b24880cbd8053ce23d5cfc42070fff29cae3bbbecf2c5c519b6bb1574b9e3e20e01badca9cc9394b30ce9d63d293953572d0d2f75a02632dc0217ab6fa05f912e9eabbed9eeccc8679c782c26a11d7bb0656930fe5b7d3d4d67d3424b7afd4212cf71b70d1e2a01299342878e350c3d82e17a5a4370adc7b7076ed87dce6b7"
	hHex := "021c1dbf7bdc24be8d2b5c56d7a3162a9a1ef824134c3a95b6d306ecd8ce90c193"
	PointchevalSigHex := "020f43b06f6500c76423ec744b28dff1a4a3594256b585265d86e6c7d307c86cc5"

	params, _ := Setup(1)
	g1, g2, p := params.g1, params.g2, params.p

	b, err := hex.DecodeString(g1Hex)
	assert.Nil(t, err)
	g1P := Curve.ECP_fromBytes(b)
	assert.True(t, g1.Equals(g1P))                    // ensure they actually represent same point on the curve
	assert.Equal(t, g1Hex, utils.ToCoconutString(g1)) // and that they have same string representation

	b, err = hex.DecodeString(g2Hex)
	assert.Nil(t, err)
	g2P := Curve.ECP2_fromBytes(b)
	assert.True(t, g2.Equals(g2P))                    // ensure they actually represent same point on the curve
	assert.Equal(t, g2Hex, utils.ToCoconutString(g2)) // and that they have same string representation

	b, err = hex.DecodeString(ordHex)
	assert.Nil(t, err)
	ordP := Curve.FromBytes(b)
	assert.Zero(t, Curve.Comp(ordP, p))               // ensure they actually represent same value
	assert.Equal(t, ordHex, utils.ToCoconutString(p)) // and that they have same string representation

	b, err = hex.DecodeString(xHex)
	assert.Nil(t, err)
	xP := Curve.FromBytes(b)

	b, err = hex.DecodeString(g1resHex)
	assert.Nil(t, err)
	g1resP := Curve.ECP_fromBytes(b)

	b, err = hex.DecodeString(XHex)
	assert.Nil(t, err)
	XP := Curve.ECP2_fromBytes(b)

	// we've already established (with previous tests) that we can recover EC points and BN from hex so we don't test for that
	g1res := Curve.G1mul(g1, xP)
	assert.True(t, g1res.Equals(g1resP))

	X := Curve.G2mul(g2, xP)
	assert.True(t, X.Equals(XP))

	b, err = hex.DecodeString(mHex)
	assert.Nil(t, err)
	m := Curve.FromBytes(b)

	b, err = hex.DecodeString(y0Hex)
	assert.Nil(t, err)
	y0 := Curve.FromBytes(b)

	b, err = hex.DecodeString(hHex)
	assert.Nil(t, err)
	hP := Curve.ECP_fromBytes(b)

	b, err = hex.DecodeString(PointchevalSigHex)
	assert.Nil(t, err)
	PointchevalSigP := Curve.ECP_fromBytes(b)

	// simple Pointcheval-Sanders signature on single public attribute
	t1 := Curve.Modmul(y0, m, p)
	K := t1.Plus(xP)
	PointchevalSig := Curve.G1mul(hP, K)
	assert.True(t, PointchevalSig.Equals(PointchevalSigP))

	sk := &SecretKey{x: xP, y: []*Curve.BIG{y0}}
	vk := &VerificationKey{g2: g2, alpha: X, beta: []*Curve.ECP2{Curve.G2mul(g2, y0)}}
	signature := &Signature{sig1: hP, sig2: PointchevalSig}
	// ensure it actually verifies
	assert.True(t, Verify(params, vk, []*Curve.BIG{m}, signature))

	_ = sk

}
