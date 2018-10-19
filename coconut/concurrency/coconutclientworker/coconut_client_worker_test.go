package coconutclientworker_test

import (
	"testing"

	"github.com/eapache/channels"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/coconutclientworker"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobworker"
	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/stretchr/testify/assert"

	"github.com/jstuczyn/CoconutGo/coconut/scheme"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

func TestCCWVerify(t *testing.T) {
	numWorkers := 2
	attrs := []string{
		"foo1",
		"foo2",
		"foo3",
		"foo4",
		"foo5",
		"foo6",
		"foo7",
		"foo8",
		"foo9",
		"foo10",
	}
	params, err := coconut.Setup(len(attrs))
	assert.Nil(t, err)

	sk, vk, err := coconut.Keygen(params)
	assert.Nil(t, err)

	attrsBig := make([]*Curve.BIG, len(attrs))
	for i := range attrs {
		attrsBig[i], err = utils.HashStringToBig(amcl.SHA256, attrs[i])
		assert.Nil(t, err)
	}
	sig, err := coconut.Sign(params, sk, attrsBig)
	assert.Nil(t, err)
	// assert.True(t, coconut.Verify(params, vk, attrsBig, sig))

	infch := channels.NewInfiniteChannel()

	ccw := coconutclientworker.New(infch)

	for i := 0; i < numWorkers; i++ {
		jobworker.New(infch.Out(), i)
	}

	assert.True(t, ccw.Verify(params, vk, attrsBig, sig))

	// ccw.DoG1Mul(g1, x, y)

}

func BenchmarkCCWVerify(b *testing.B) {
	numWorkers := 3
	attrs := []string{
		"foo1",
		"foo2",
		"foo3",
		"foo4",
		"foo5",
		"foo6",
		"foo7",
		"foo8",
		"foo9",
		"foo10",
	}
	params, _ := coconut.Setup(len(attrs))
	sk, vk, _ := coconut.Keygen(params)

	attrsBig := make([]*Curve.BIG, len(attrs))
	for i := range attrs {
		attrsBig[i], _ = utils.HashStringToBig(amcl.SHA256, attrs[i])
	}
	sig, _ := coconut.Sign(params, sk, attrsBig)

	infch := channels.NewInfiniteChannel()
	ccw := coconutclientworker.New(infch)

	for i := 0; i < numWorkers; i++ {
		jobworker.New(infch.Out(), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccw.Verify(params, vk, attrsBig, sig)
	}
}
