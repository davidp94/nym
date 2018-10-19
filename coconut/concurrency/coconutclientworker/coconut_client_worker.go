package coconutclientworker

import (
	"fmt"
	"sync"

	"github.com/eapache/channels"
	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobpacket"

	// coconut "github.com/jstuczyn/CoconutGo/coconut/scheme"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

type MuxBpGroup struct {
	bpgroup.BpGroup
	mux sync.Mutex
}

type CoconutClientWorker struct {
	jobQueue *channels.InfiniteChannel
}

func (ccw *CoconutClientWorker) DoG1Mul(g1 *Curve.ECP, x *Curve.BIG, y *Curve.BIG) {

	outCh := make(chan interface{}, 2)

	op1 := func() (interface{}, error) {
		return Curve.G1mul(g1, x), nil
	}

	op2 := func() (interface{}, error) {
		return Curve.G1mul(g1, y), nil
	}

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

func New(jobQueue *channels.InfiniteChannel) *CoconutClientWorker {
	return &CoconutClientWorker{
		jobQueue: jobQueue,
	}
}
