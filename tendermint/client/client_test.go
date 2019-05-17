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
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/query"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymnode/testnode"
	"github.com/stretchr/testify/assert"
	cmn "github.com/tendermint/tendermint/libs/common"
)

const tendermintRPCPort = 36657

// TODO: create entire cluster
//nolint: gochecknoglobals
var addresses = []string{
	"localhost:4667",
	fmt.Sprintf("localhost:%v", tendermintRPCPort),
}

// TEST REQUIRES RUNNING WITH --race FLAG
func TestMultipleQueries(t *testing.T) {
	log, err := logger.New("", "DEBUG", true)
	// log, err := logger.New("", "DEBUG", false)

	assert.Nil(t, err)

	nymClient, err := New(addresses, log)
	assert.Nil(t, err)

	var wg sync.WaitGroup
	numWorkers := 50
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			_, _ = nymClient.Query(query.QueryCheckBalancePath, []byte("foo"))
			wg.Done()
		}()
	}
	wg.Wait()
}

// TODO: more tests

func TestMain(m *testing.M) {
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("test-node-%v", cmn.RandStr(6)))
	if err != nil {
		log.Fatal(err)
	}

	node, err := testnode.CreateTestingNymNode(tmpDir, tendermintRPCPort-1)
	if err != nil {
		log.Fatal(err)
	}
	if err := node.Start(); err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpDir)

	runTests := m.Run()

	if err := node.Stop(); err != nil {
		fmt.Println("Undefined behaviour - node was somehow already stopped")
	}
	os.RemoveAll(tmpDir)

	os.Exit(runTests)
}
