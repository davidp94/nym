// jobqueue.go - Queue implementation for putting seemingly infinite number of jobs onto a channel
// Copyright (C) 2019  Jedrzej Stuczynski.
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

// Package jobqueue is implemented based on eapache's infinite channel template:
// https://github.com/eapache/channels/blob/master/infinite_channel.go
// As explained by the author in documentation: https://godoc.org/github.com/eapache/channels due to Go's type system
// limitations direct import of his library is impractical.
// This reimplementation allows more type safety due to having more strict channel type than an empty interface.
// On top of better, even though slightly slower, queue as now it is thread-safe which is crucial as the jobqueue
// can be read by multiple workers.
// NOTE: this file will be later moved
package jobqueue

import (
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	"github.com/Workiva/go-datastructures/queue"
)

// minQueueLen is the smallest capacity that queue may have.
const minQueueLen = 16

// JobQueue represents a seemingly 'infinite' (depending on available memory) FIFO queue working on JobPacket items.
type JobQueue struct {
	input  chan *jobpacket.JobPacket
	output chan *jobpacket.JobPacket
	length chan int64
	buffer *queue.Queue
}

// In returns input channel for writing JobPackets.
func (jq *JobQueue) In() chan<- *jobpacket.JobPacket {
	return jq.input
}

// Out returns output channel for reading JobPackets.
func (jq *JobQueue) Out() <-chan *jobpacket.JobPacket {
	return jq.output
}

// Len returns number of elements in the queue.
func (jq *JobQueue) Len() int64 {
	return <-jq.length
}

// Close closes the input channel, however, output and hence the goroutine will be open until the queue is exhausted.
func (jq *JobQueue) Close() {
	close(jq.input)
}

func (jq *JobQueue) infiniteBuffer() {
	var input, output chan *jobpacket.JobPacket
	var next *jobpacket.JobPacket
	input = jq.input

	for input != nil || output != nil {
		select {
		case elem, open := <-input:
			if open {
				err := jq.buffer.Put(elem)
				if err != nil {
					// there is nothing more we can do,
					// if we don't panic, all workers will block trying to read/write to closed channels.
					// Moreover the error should never be returned during normal operations.
					panic(fmt.Sprintf("The JobQueue is in invalid state: %v", err))
				}
			} else {
				input = nil
			}
		case output <- next:
			_, err := jq.buffer.Get(1)
			// same rationale as with previous panics
			if err != nil {
				panic(fmt.Sprintf("The JobQueue is in invalid state: %v", err))
			}
		case jq.length <- jq.buffer.Len():
		}

		if jq.buffer.Len() > 0 {
			output = jq.output
			nextT, err := jq.buffer.Peek()

			if err != nil {
				// Error can only happen if either the queue is already disposed what similarly to input should have
				// never happened accidentally and then there's nothing we can really do or if there are no items in the
				// queue which is also impossible due to explicit check.
				panic(fmt.Sprintf("The JobQueue is in invalid state: %v", err))
			}
			next = nextT.(*jobpacket.JobPacket)

		} else {
			output = nil
			next = nil
		}
	}

	close(jq.output)
	close(jq.length)
}

// New creates a new instance of a JobQueue.
func New() *JobQueue {
	jq := &JobQueue{
		input:  make(chan *jobpacket.JobPacket),
		output: make(chan *jobpacket.JobPacket),
		length: make(chan int64),
		buffer: queue.New(minQueueLen),
	}

	go jq.infiniteBuffer()
	return jq
}
