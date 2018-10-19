package coconutclientworker

import (
	"fmt"
	"sync"

	"github.com/eapache/channels"
	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobpacket"

	"github.com/jstuczyn/CoconutGo/coconut/scheme"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

type MuxBpGroup struct {
	bpgroup.BpGroup
	mux sync.Mutex
}

type CoconutClientWorker struct {
	// todo: does it need to be able to both read and write ?
	jobQueue *channels.InfiniteChannel
}

func (ccw *CoconutClientWorker) DoG1Mul(g1 *Curve.ECP, x *Curve.BIG, y *Curve.BIG) {
	// should that channel be even buffered?
	outCh := make(chan interface{}, 2)

	op1 := jobpacket.MakeG1MulOp(g1, x)
	op2 := jobpacket.MakeG1MulOp(g1, y)

	packet1 := jobpacket.New(outCh, op1)
	packet2 := jobpacket.New(outCh, op2)

	ccw.jobQueue.In() <- packet1
	ccw.jobQueue.In() <- packet2

	var res1 *Curve.ECP
	var res2 *Curve.ECP

	for {
		// both results were written
		if len(outCh) == 2 {
			// todo switch for err type etc
			res1t := <-outCh
			res2t := <-outCh
			res1 = res1t.(*Curve.ECP)
			res2 = res2t.(*Curve.ECP)

			fmt.Println(res1.ToString())
			fmt.Println(res2.ToString())
		}
	}

}

func (ccw *CoconutClientWorker) Verify(params *coconut.Params, vk *coconut.VerificationKey, pubM []*Curve.BIG, sig *coconut.Signature) bool {
	outCh := make(chan interface{})

	if len(pubM) != len(vk.Beta()) {
		return false
	}

	K := Curve.NewECP2()
	K.Copy(vk.Alpha()) // K = X

	// in this case ordering does not matter at all, since we're adding all results together
	for i := 0; i < len(pubM); i++ {
		// change structure of jobpacket to fix that monstrosity...
		ccw.jobQueue.In() <- jobpacket.New(outCh, jobpacket.MakeG2MulOp(vk.Beta()[i], pubM[i]))
	}
	for i := 0; i < len(pubM); i++ {
		res := <-outCh
		g2E := res.(*Curve.ECP2)
		K.Add(g2E) // K = X + (a1 * Y1) + ...
	}

	pairOp1 := jobpacket.MakePairingOp(sig.Sig1(), K)
	pairOp2 := jobpacket.MakePairingOp(sig.Sig2(), vk.G2())

	ccw.jobQueue.In() <- jobpacket.New(outCh, pairOp1)
	ccw.jobQueue.In() <- jobpacket.New(outCh, pairOp2)

	// we can evaluate that while waiting for valuation of both pairings
	exp1 := !sig.Sig1().Is_infinity()

	res1 := <-outCh
	res2 := <-outCh
	gt1 := res1.(*Curve.FP12)
	gt2 := res2.(*Curve.FP12)

	exp2 := gt1.Equals(gt2)

	return exp1 && exp2
}

func New(jobQueue *channels.InfiniteChannel) *CoconutClientWorker {
	return &CoconutClientWorker{
		jobQueue: jobQueue,
	}
}
