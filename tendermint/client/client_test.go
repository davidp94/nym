// client_test.go - tests for tendermint client
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

package client

import (
	"sync"
	"testing"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/query"

	"0xacab.org/jstuczyn/CoconutGo/logger"
	"github.com/stretchr/testify/assert"
)

var addresses = []string{
	"localhost:4667",

	"localhost:46657",
	"localhost:46667",
	"localhost:46677",
	"localhost:46687",
}

func init() {
	// will startup dummy tendermint nodes
}

func TestBasic(t *testing.T) {
	// log, err := logger.New("", "DEBUG", true)
	log, err := logger.New("", "DEBUG", false)

	assert.Nil(t, err)

	nymClient, err := New(addresses, log)
	assert.Nil(t, err)

	// time for me to kill the node and cause reconnect
	time.Sleep(time.Second * 5)

	var wg sync.WaitGroup

	numWorkers := 10

	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			_, _ = nymClient.Query(query.QueryCheckBalancePath, []byte("foo"))
			wg.Done()
		}()
	}
	wg.Wait()
}
