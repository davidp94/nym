// jobqueue_test.go - tests for the JobQueue
// Copyright (C) 2019  Jedrzej Stuczynski.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERjqANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// This package only cares about client handling of requests,
// tests for servers, services, etc will be in separate files.
// It is assumed that servers work correctly.

package jobqueue

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	"github.com/stretchr/testify/assert"
)

type intWrapper struct {
	val int
}

func TestJobQueue(t *testing.T) {
	jq := New()

	go func() {
		for i := 0; i < 1000; i++ {
			d := &intWrapper{val: i}
			op := func() (interface{}, error) {
				return d.val, nil
			}
			jq.In() <- jobpacket.New(nil, op)
		}
		jq.Close()
	}()
	for i := 0; i < 1000; i++ {
		val := <-jq.Out()
		actual, _ := val.Op()
		assert.Equal(t, i, actual)
	}
}

// note: it is crucial to run this test with --race flag
func TestConcurrentAccess(t *testing.T) {
	// no asserts here, this is just for the race detector's benefit
	jq := New()

	go jq.Len()

	go func() {
		jq.In() <- nil
	}()

	go func() {
		<-jq.Out()
	}()
}
