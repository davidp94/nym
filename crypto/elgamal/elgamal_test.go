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

	"github.com/jstuczyn/CoconutGo/crypto/bpgroup"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
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

func TestElGamalNewEncryptionFromPoints(t *testing.T) {
	G := bpgroup.New()
	p, g1, rng := G.Order(), G.Gen1(), G.Rng()

	d, gamma := Keygen(G)

	// encrypt random message
	t1 := Curve.Randomnum(p, rng)
	h := Curve.G1mul(g1, t1)
	m := Curve.Randomnum(p, rng)
	hm := Curve.G1mul(h, m)

	enc, _ := Encrypt(G, gamma, m, h)
	// multiply encryption by random scalar
	r := Curve.Randomnum(p, rng)
	c1 := Curve.G1mul(enc.C1(), r)
	c2 := Curve.G1mul(enc.C2(), r)
	enc2 := NewEncryptionFromPoints(c1, c2)

	// ensure it still decrypts correctly
	dec := Decrypt(G, d, enc2)
	hm = Curve.G1mul(hm, r)
	assert.True(t, dec.Equals(hm), "Original message (multiplied by same scalar) should be recovered")
}

var kencRes *Curve.BIG

func BenchmarkElGamalEncryption(b *testing.B) {
	var k *Curve.BIG
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		G := bpgroup.New()
		_, gamma := Keygen(G)
		m := Curve.Randomnum(G.Order(), G.Rng())
		t := Curve.Randomnum(G.Order(), G.Rng())
		h := Curve.G1mul(G.Gen1(), t)
		b.StartTimer()
		_, k = Encrypt(G, gamma, m, h)
	}
	kencRes = k
}

var decRes *Curve.ECP

func BenchmarkElGamalDecryption(b *testing.B) {
	var dec *Curve.ECP
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		G := bpgroup.New()
		d, gamma := Keygen(G)
		m := Curve.Randomnum(G.Order(), G.Rng())
		t := Curve.Randomnum(G.Order(), G.Rng())
		h := Curve.G1mul(G.Gen1(), t)
		enc, _ := Encrypt(G, gamma, m, h)
		b.StartTimer()
		dec = Decrypt(G, d, enc)
	}
	decRes = dec
}
