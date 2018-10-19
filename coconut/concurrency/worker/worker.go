package worker

import (
	"sync"
)

// for now copied from https://github.com/katzenpost/core/blob/master/worker/worker.go
// todo: remove unneccsary bits

type Worker struct {
	sync.WaitGroup
	initOnce sync.Once

	haltCh chan interface{}
}

func (w *Worker) Go(fn func()) {
	w.initOnce.Do(w.init)
	w.Add(1)
	go func() {
		defer w.Done()
		fn()
	}()
}

func (w *Worker) Halt() {
	w.initOnce.Do(w.init)
	close(w.haltCh)
	w.Wait()
}

func (w *Worker) HaltCh() <-chan interface{} {
	w.initOnce.Do(w.init)
	return w.haltCh
}

func (w *Worker) init() {
	w.haltCh = make(chan interface{})
}
