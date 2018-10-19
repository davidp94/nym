package jobworker

import (
	"fmt"

	"github.com/jstuczyn/CoconutGo/coconut/concurrency/jobpacket"
	"github.com/jstuczyn/CoconutGo/coconut/concurrency/worker"
)

type Worker struct {
	worker.Worker

	id       int
	jobQueue <-chan interface{}
}

func (w *Worker) worker() {
	for {
		var jobpkt *jobpacket.JobPacket
		select {
		case e := <-w.jobQueue:
			jobpkt = e.(*jobpacket.JobPacket)
		}
		fmt.Println("Worker id", w.id)

		res, err := jobpkt.Op()
		if err != nil {
			jobpkt.OutCh <- err
		} else {
			jobpkt.OutCh <- res
		}
	}
}

func New(jobQueue <-chan interface{}, id int) *Worker {
	w := &Worker{
		jobQueue: jobQueue,
		id:       id,
	}

	// how come this is working if w.worker object was never created
	w.Go(w.worker)
	return w
}
