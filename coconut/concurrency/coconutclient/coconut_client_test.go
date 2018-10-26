package coconutclient_test

import (
	"testing"

	"github.com/eapache/channels"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/coconutclient"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobworker"
	coconut "github.com/jstuczyn/CoconutGo/coconut/scheme"
	. "github.com/jstuczyn/CoconutGo/testutils"
	"github.com/stretchr/testify/assert"
)

// those are currently only very crude tests
// todo: make them look proper, with decent vectors etc

const NUM_WORKERS = 2

var jobCh *channels.InfiniteChannel
var ccw *coconutclient.Worker

func init() {
	jobCh = channels.NewInfiniteChannel()
	ccw = coconutclient.New(jobCh.In())

	for i := 0; i < NUM_WORKERS; i++ {
		jobworker.New(jobCh.Out(), uint64(i))
	}
}

func TestCCWSetup(t *testing.T) {
	_, err := ccw.Setup(0)
	assert.Equal(t, coconut.ErrSetupParams, err, "Should not allow generating params for less than 1 attribute")

	params, err := ccw.Setup(10)
	assert.Nil(t, err)
	assert.Len(t, params.Hs(), 10)
}

func TestCCWKeygen(t *testing.T) {
	params, err := ccw.Setup(10)
	assert.Nil(t, err)

	sk, vk, err := ccw.Keygen(params)
	assert.Nil(t, err)

	TestKeygenProperties(t, params, sk, vk)
}

func TestCCWTTPKeygen(t *testing.T) {
	params, err := ccw.Setup(10)
	assert.Nil(t, err)

	_, _, err = ccw.TTPKeygen(params, 6, 5)
	assert.Equal(t, coconut.ErrTTPKeygenParams, err)

	_, _, err = ccw.TTPKeygen(params, 0, 6)
	assert.Equal(t, coconut.ErrTTPKeygenParams, err)

	tests := []struct {
		t int
		n int
	}{
		{1, 6},
		{3, 6},
		{6, 6},
	}
	for _, test := range tests {
		repeat := 3
		q := 4
		params, _ := ccw.Setup(q)

		sks, vks, err := ccw.TTPKeygen(params, test.t, test.n)
		assert.Nil(t, err)
		assert.Equal(t, len(sks), len(vks))

		// first check if they work as normal keys
		for i := range sks {
			TestKeygenProperties(t, params, sks[i], vks[i])
		}

		for i := 0; i < repeat; i++ {
			TestTTPKeygenProperties(t, params, sks, vks, test.t, test.n)
		}
	}
}

func TestCCWSign(t *testing.T) {
	TestSign(t, ccw)
}

func TestCCWVerify(t *testing.T) {
	TestVerify(t, ccw)
}

func TestCCWRandomize(t *testing.T) {
	TestRandomize(t, ccw)
}

func TestCCWKeyAggregation(t *testing.T) {
	TestKeyAggregation(t, ccw)
}

func TestCCWAggregateVerification(t *testing.T) {
	TestAggregateVerification(t, ccw)
}

func TestCCWSignerProof(t *testing.T) {
	TestSignerProof(t, ccw)
}

func TestCCWVerifierProof(t *testing.T) {
	TestVerifierProof(t, ccw)
}

func TestCCWBlindVerify(t *testing.T) {
	TestBlindVerify(t, ccw)
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
// 	ccw := coconutclient.New(infch.In())

// 	for i := 0; i < numWorkers; i++ {
// 		jobworker.New(infch.Out(), uint64(i))
// 	}

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		ccw.Verify(params, vk, attrsBig, sig)
// 	}
// }
