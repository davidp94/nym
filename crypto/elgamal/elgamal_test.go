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

package elgamal_test

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

func TestElGamalKeygen(t *testing.T) {
	G := bpgroup.New()
	g1 := G.Gen1()
	pk, pub := elgamal.Keygen(G)

	assert.True(t, pub.Gamma().Equals(Curve.G1mul(g1, pk.D())), "Gamma should be equal to g1 * d")
}

func TestElGamalEncryption(t *testing.T) {
	G := bpgroup.New()
	p, g1, rng := G.Order(), G.Gen1(), G.Rng()

	_, pub := elgamal.Keygen(G)

	t1 := Curve.Randomnum(p, rng)
	h := Curve.G1mul(g1, t1) // random h
	m := Curve.Randomnum(p, rng)

	enc, k := elgamal.Encrypt(G, pub, m, h)

	assert.True(t, enc.C1().Equals(Curve.G1mul(g1, k)), "a should be equal to g1^k")

	tmp := Curve.G1mul(pub.Gamma(), k) // b = (k * gamma)
	tmp.Add(Curve.G1mul(h, m))         // b = (k * gamma) + (m * h)

	assert.True(t, enc.C2().Equals(tmp), "b should be equal to (k * gamma) + (m * h)")
}

func TestElGamalDecryption(t *testing.T) {
	G := bpgroup.New()
	p, g1, rng := G.Order(), G.Gen1(), G.Rng()

	pk, pub := elgamal.Keygen(G)

	t1 := Curve.Randomnum(p, rng)
	h := Curve.G1mul(g1, t1) // random h
	m := Curve.Randomnum(p, rng)
	hm := Curve.G1mul(h, m)

	enc, _ := elgamal.Encrypt(G, pub, m, h)
	dec := elgamal.Decrypt(G, pk, enc)

	assert.True(t, dec.Equals(hm), "Original message should be recovered")
}

func TestElGamalNewEncryptionFromPoints(t *testing.T) {
	G := bpgroup.New()
	p, g1, rng := G.Order(), G.Gen1(), G.Rng()

	pk, pub := elgamal.Keygen(G)

	// encrypt random message
	t1 := Curve.Randomnum(p, rng)
	h := Curve.G1mul(g1, t1)
	m := Curve.Randomnum(p, rng)
	hm := Curve.G1mul(h, m)

	enc, _ := elgamal.Encrypt(G, pub, m, h)
	// multiply encryption by random scalar
	r := Curve.Randomnum(p, rng)
	c1 := Curve.G1mul(enc.C1(), r)
	c2 := Curve.G1mul(enc.C2(), r)
	enc2 := elgamal.NewEncryptionFromPoints(c1, c2)

	// ensure it still decrypts correctly
	dec := elgamal.Decrypt(G, pk, enc2)
	hm = Curve.G1mul(hm, r)
	assert.True(t, dec.Equals(hm), "Original message (multiplied by same scalar) should be recovered")
}

func TestPublicKeyMarshal(t *testing.T) {
	G := bpgroup.New()
	_, pub := elgamal.Keygen(G)

	data, err := pub.MarshalBinary()
	assert.Nil(t, err)

	recoveredPub := &elgamal.PublicKey{}
	assert.Nil(t, recoveredPub.UnmarshalBinary(data))
	assert.True(t, pub.G().Equals(recoveredPub.G()))
	assert.True(t, pub.Gamma().Equals(recoveredPub.Gamma()))
	assert.Zero(t, Curve.Comp(recoveredPub.P(), pub.P()))

}

func TestPrivateKeyMarshal(t *testing.T) {
	G := bpgroup.New()
	pk, _ := elgamal.Keygen(G)

	data, err := pk.MarshalBinary()
	assert.Nil(t, err)

	recoveredPK := &elgamal.PrivateKey{}
	assert.Nil(t, recoveredPK.UnmarshalBinary(data))
	assert.Zero(t, Curve.Comp(recoveredPK.D(), pk.D()))
}

//nolint: gochecknoglobals
var kencRes *Curve.BIG

func BenchmarkElGamalEncryption(b *testing.B) {
	var k *Curve.BIG
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		G := bpgroup.New()
		_, pub := elgamal.Keygen(G)
		m := Curve.Randomnum(G.Order(), G.Rng())
		t := Curve.Randomnum(G.Order(), G.Rng())
		h := Curve.G1mul(G.Gen1(), t)
		b.StartTimer()
		_, k = elgamal.Encrypt(G, pub, m, h)
	}
	kencRes = k
}

//nolint: gochecknoglobals
var decRes *Curve.ECP

func BenchmarkElGamalDecryption(b *testing.B) {
	var dec *Curve.ECP
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		G := bpgroup.New()
		pk, pub := elgamal.Keygen(G)
		m := Curve.Randomnum(G.Order(), G.Rng())
		t := Curve.Randomnum(G.Order(), G.Rng())
		h := Curve.G1mul(G.Gen1(), t)
		enc, _ := elgamal.Encrypt(G, pub, m, h)
		b.StartTimer()
		dec = elgamal.Decrypt(G, pk, enc)
	}
	decRes = dec
}
