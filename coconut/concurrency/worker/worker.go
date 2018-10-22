// for now copied from https://github.com/katzenpost/core/blob/master/worker/worker.go
// todo: remove unneccsary bits
// todo: how does license work for copied code?

package worker

import "sync"

// Worker is a set of managed background go routines.
type Worker struct {
	sync.WaitGroup
	initOnce sync.Once

	haltCh chan interface{}
}

// Go excutes the function fn in a new Go routine.  Multiple Go routines may
// be started under the same Worker.  It is the function's responsiblity to
// monitor the channel returned by `Worker.HaltCh()` and to return.
func (w *Worker) Go(fn func()) {
	w.initOnce.Do(w.init)
	w.Add(1)
	go func() {
		defer w.Done()
		fn()
	}()
}

// Halt signals all Go routines started under a Worker to terminate, and waits
// till all go routines have returned.
func (w *Worker) Halt() {
	w.initOnce.Do(w.init)
	close(w.haltCh)
	w.Wait()
}

// HaltCh returns the channel that will be closed on a call to Halt.
func (w *Worker) HaltCh() <-chan interface{} {
	w.initOnce.Do(w.init)
	return w.haltCh
}

func (w *Worker) init() {
	w.haltCh = make(chan interface{})
}
