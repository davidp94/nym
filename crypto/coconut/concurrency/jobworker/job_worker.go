// job_worker.go - Worker for job queue tasks.
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

// Package jobworker implements worker for performing tasks defined by jobpacket that are in the queue.
package jobworker

import (
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"gopkg.in/op/go-logging.v1"
)

// JobWorker is an instance of jobWorker.
type JobWorker struct {
	worker.Worker

	id       uint64
	jobQueue <-chan interface{}

	log *logging.Logger
}

func (jw *JobWorker) worker() {
	for {
		var jobpkt *jobpacket.JobPacket
		select {
		case <-jw.HaltCh():
			jw.log.Debugf("Halting worker %d\n", jw.id)
			return
		case e := <-jw.jobQueue:
			jw.log.Debug("Got JobPacket")
			jobpkt = e.(*jobpacket.JobPacket)
		}

		res, err := jobpkt.Op()
		jw.log.Debug("Finished working on the JobPacket")
		// job provider will be able to distinguish those cases thanks to type assertions
		if err != nil {
			jobpkt.OutCh <- err
		} else {
			jobpkt.OutCh <- res
		}
	}
}

// New creates new instance of a jobWorker.
func New(jobQueue <-chan interface{}, id uint64, l *logger.Logger) *JobWorker {
	jw := &JobWorker{
		jobQueue: jobQueue,
		id:       id,
		log:      l.GetLogger(fmt.Sprintf("CoconutJobWorker:%d", int(id))),
	}

	jw.Go(jw.worker)
	return jw
}
