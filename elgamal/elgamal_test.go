// elgamal_test.go - ElGamal encryption scheme tests
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

package elgamal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BN254"
)

func TestElGamalKeygen(t *testing.T) {
	G := bpgroup.New()
	g1 := G.Gen1()
	d, gamma := Keygen(G)

	assert.True(t, gamma.Equals(Curve.G1mul(g1, d)), "Gamma should be equal to g1 * d")
}

func TestElGamalEncryption(t *testing.T) {
	G := bpgroup.New()
	p, g1, rng := G.Order(), G.Gen1(), G.Rng()

	_, gamma := Keygen(G)

	t1 := Curve.Randomnum(p, rng)
	h := Curve.G1mul(g1, t1) // random h
	m := Curve.Randomnum(p, rng)

	enc, k := Encrypt(G, gamma, m, h)

	assert.True(t, enc.c1.Equals(Curve.G1mul(g1, k)), "a should be equal to g1^k")

	tmp := Curve.G1mul(gamma, k) // b = (k * gamma)
	tmp.Add(Curve.G1mul(h, m))   // b = (k * gamma) + (m * h)

	assert.True(t, enc.c2.Equals(tmp), "b should be equal to (k * gamma) + (m * h)")
}

func TestElGamalDecryption(t *testing.T) {
	G := bpgroup.New()
	p, g1, rng := G.Order(), G.Gen1(), G.Rng()

	d, gamma := Keygen(G)

	t1 := Curve.Randomnum(p, rng)
	h := Curve.G1mul(g1, t1) // random h
	m := Curve.Randomnum(p, rng)
	hm := Curve.G1mul(h, m)

	enc, _ := Encrypt(G, gamma, m, h)
	dec := Decrypt(G, d, enc)

	assert.True(t, dec.Equals(hm), "Original message should be recovered")
}
