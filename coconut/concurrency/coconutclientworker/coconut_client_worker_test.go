package coconutclientworker_test

import (
	"testing"

	"github.com/eapache/channels"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/coconutclientworker"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobworker"
	. "github.com/jstuczyn/CoconutGo/testutils"
	"github.com/stretchr/testify/assert"
)

// those are currently only very crude tests
// todo: make them look proper, with decent vectors etc

// func TestCCWVerify(t *testing.T) {
// 	numWorkers := 2
// 	attrs := []string{
// 		"foo1",
// 		"foo2",
// 		"foo3",
// 		"foo4",
// 		"foo5",
// 		"foo6",
// 		"foo7",
// 		"foo8",
// 		"foo9",
// 		"foo10",
// 	}
// 	params, err := coconut.Setup(len(attrs))
// 	assert.Nil(t, err)

// 	sk, vk, err := coconut.Keygen(params)
// 	assert.Nil(t, err)

// 	attrsBig := make([]*Curve.BIG, len(attrs))
// 	for i := range attrs {
// 		attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, attrs[i])
// 		assert.Nil(t, err)
// 	}
// 	sig, err := coconut.Sign(params, sk, attrsBig)
// 	assert.Nil(t, err)
// 	// assert.True(t, coconut.Verify(params, vk, attrsBig, sig))

// 	infch := channels.NewInfiniteChannel()
// 	ccw := coconutclientworker.New(infch.In())

// 	for i := 0; i < numWorkers; i++ {
// 		jobworker.New(infch.Out(), uint64(i))
// 	}

// 	assert.True(t, ccw.Verify(params, vk, attrsBig, sig))

// 	// ccw.DoG1Mul(g1, x, y)

// }

func TestCCWKeygen(t *testing.T) {
	numWorkers := 2
	q := 5

	infch := channels.NewInfiniteChannel()
	ccw := coconutclientworker.New(infch.In())

	for i := 0; i < numWorkers; i++ {
		jobworker.New(infch.Out(), uint64(i))
	}

	muxParams, err := ccw.Setup(q)
	assert.Nil(t, err)

	sk, vk, err := ccw.Keygen(muxParams)
	assert.Nil(t, err)
	TestKeygenProperties(t, muxParams, sk, vk)
}

// todo: proper test vectors
func TestCCWTTPKeygen(t *testing.T) {
	numWorkers := 2
	repeat := 3
	q := 5
	k := 2
	n := 5

	infch := channels.NewInfiniteChannel()
	ccw := coconutclientworker.New(infch.In())

	for i := 0; i < numWorkers; i++ {
		jobworker.New(infch.Out(), uint64(i))
	}

	muxParams, err := ccw.Setup(q)
	assert.Nil(t, err)

	sks, vks, err := ccw.TTPKeygen(muxParams, k, n)
	assert.Nil(t, err)
	assert.Equal(t, len(sks), len(vks))
	for i := range sks {
		TestKeygenProperties(t, muxParams, sks[i], vks[i])
	}

	for i := 0; i < repeat; i++ {
		TestTTPKeygenProperties(t, muxParams, sks, vks, k, n)
	}

}

// func BenchmarkCCWVerify(b *testing.B) {
// 	numWorkers := 1
// 	attrs := []string{
// 		"foo1",
// 		"foo2",
// 		"foo3",
// 		"foo4",
// 		"foo5",
// 		"foo6",
// 		"foo7",
// 		"foo8",
// 		"foo9",
// 		"foo10",
// 	}
// 	params, _ := coconut.Setup(len(attrs))
// 	sk, vk, _ := coconut.Keygen(params)

// 	attrsBig := make([]*Curve.BIG, len(attrs))
// 	for i := range attrs {
// 		attrsBig[i], _ = utils.HashStringToBig(amcl.SHA256, attrs[i])
// 	}
// 	sig, _ := coconut.Sign(params, sk, attrsBig)

// 	infch := channels.NewInfiniteChannel()
// 	ccw := coconutclientworker.New(infch.In())

// 	for i := 0; i < numWorkers; i++ {
// 		jobworker.New(infch.Out(), uint64(i))
// 	}

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		ccw.Verify(params, vk, attrsBig, sig)
// 	}
// }
