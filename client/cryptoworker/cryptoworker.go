// cryptoworker.go - Coconut Worker for Coconut client.
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

// Package cryptoworker combines coconut worker and job workers for a client instance.
package cryptoworker

import (
	"github.com/eapache/channels"
	"gopkg.in/op/go-logging.v1"

	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
)

// Worker allows writing coconut actions to a shared job queue,
// so that they could be run concurrently.
type Worker struct {
	cw  *coconutworker.CoconutWorker
	log *logging.Logger
	id  uint64

	jobWorkers []*jobworker.Worker
}

// CoconutWorker returns coconut worker instance associated with cryptoworker.
func (w *Worker) CoconutWorker() *coconutworker.CoconutWorker {
	return w.cw
}

// Halt cleanly shuts down a given cryptoworker instance.
func (w *Worker) Halt() {
	for i, wrk := range w.jobWorkers {
		if wrk != nil {
			wrk.Halt()
			w.jobWorkers[i] = nil
		}
	}
	w.log.Notice("Stopped all job workers.")
}

// New creates new instance of a coconutWorker.
// nolint: lll
func New(id uint64, l *logger.Logger, params *coconut.Params, numWorkers int) *Worker {
	jobCh := channels.NewInfiniteChannel() // commands issued by coconutworkers, like do pairing, g1mul, etc
	cw := coconutworker.New(jobCh.In(), params)

	w := &Worker{
		cw:  cw,
		log: l.GetLogger(fmt.Sprintf("Clientcryptoworker:%d", int(id))),
		id:  id,
	}

	jobworkers := make([]*jobworker.Worker, numWorkers)
	for i := range jobworkers {
		jobworkers[i] = jobworker.New(jobCh.Out(), uint64(i+1), l)
	}
	w.log.Noticef("Started %v Job Worker(s)", numWorkers)

	return w
}
