package coconutworker_test

import (
	"os"
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobqueue"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	. "0xacab.org/jstuczyn/CoconutGo/crypto/testutils"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"github.com/stretchr/testify/assert"
)

// todo: ensure results returned by ccw.Method() are the same as by coconut.Function()

const numWorkers = 6

//nolint: gochecknoglobals
var (
	workers []*jobworker.JobWorker
	ccw     *coconutworker.CoconutWorker
	log     *logger.Logger
)

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

		tsks, tvks, err := ccw.TTPKeygen(params, test.t, test.n)
		assert.Nil(t, err)
		assert.Equal(t, len(tsks), len(tvks))

		// TODO: proper handle
		sks := make([]*coconut.SecretKey, len(tsks))
		for i := range tsks {
			sks[i] = tsks[i].SecretKey
		}
		vks := make([]*coconut.VerificationKey, len(tvks))
		for i := range tvks {
			vks[i] = tvks[i].VerificationKey
		}

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

func TestCCWThresholdAuthorities(t *testing.T) {
	TestThresholdAuthorities(t, ccw)
}

func TestCCWTumblerProof(t *testing.T) {
	TestTumblerProof(t, ccw)
}

func TestSchemeBlindVerifyTumbler(t *testing.T) {
	TestBlindVerifyTumbler(t, ccw)
}

func TestMain(m *testing.M) {
	var err error
	log, err = logger.New("", "DEBUG", true)
	if err != nil {
		panic(err)
	}

	jobqueue := jobqueue.New()

	params, err := coconut.Setup(10)
	if err != nil {
		panic(err)
	}

	ccw = coconutworker.New(jobqueue.In(), params)

	for i := 0; i < numWorkers; i++ {
		workers = append(workers, jobworker.New(jobqueue.Out(), uint64(i), log))
	}

	runTests := m.Run()

	os.Exit(runTests)
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
