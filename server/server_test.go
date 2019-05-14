// server_test.go - tests for coconut server API
// Copyright (C) 2018-2019  Jedrzej Stuczynski.
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
package server

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/server/config"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymnode/testnode"
	"github.com/stretchr/testify/assert"
	cmn "github.com/tendermint/tendermint/libs/common"
)

type providerServer struct {
	tcpaddress  string
	grpcaddress string
	server      *Server
}

const issuersKeysFolderRelative = "../testdata/issuerkeys"
const thresholdVal = 3 // defined by the pre-generated keys
const tendermintRPCPort = 36657

var issuersKeysFolder string
var issuers []*Server
var thresholdProvider *providerServer
var nonThresholdProvider *providerServer

var providerStartupRetryInterval = 1 * 1500
var providerStartupTimeout = 5 * 1000 // lower it for the test
var connectionTimeout = 1 * 1000      // to more quickly figure out issuer is down

var issuerTCPAddresses = []string{
	"127.0.0.1:6100",
	"127.0.0.1:6101",
	"127.0.0.1:6102",
	"127.0.0.1:6103",
	"127.0.0.1:6104",
}

var issuerGRPCAddresses = []string{
	"127.0.0.1:6200",
	"127.0.0.1:6201",
	"127.0.0.1:6202",
	"127.0.0.1:6203",
	"127.0.0.1:6204",
}

var providerTCPAddresses = []string{
	"127.0.0.1:7100",
	"127.0.0.1:7101",
}
var providerGRPCAddresses = []string{
	"127.0.0.1:7200", // threshold
	"127.0.0.1:7201", // nonthreshold
}

func makeStringOfAddresses(name string, addrs []string) string {
	out := name + " = ["
	for i, addr := range addrs {
		out += fmt.Sprintf("\"%v\"", addr)
		if i != len(addrs)-1 {
			out += ","
		}
	}
	out += "]"
	return out
}

// creates a very dummy test server that always returns predefined 'res'
func dummyServer(res []byte, address string) net.Listener {
	l, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	go func() {
		defer l.Close()
		for {

			conn, err := l.Accept()
			if err != nil {
				// conn error happens on closing listener, so we can abuse that to terminate the goroutine
				return
			}

			// dont even bother reading request
			conn.Write(res)
			conn.Close()
		}
	}()

	return l
}

func startProvider(addr string, grpcaddr string, threshold bool, tmpDir string) *Server {
	IAAddressesStr := makeStringOfAddresses("IAAddresses", issuerTCPAddresses)
	thresholdStr := ""
	if threshold {
		thresholdStr = fmt.Sprintf("Threshold = %v\n", thresholdVal)
	} else {
		thresholdStr = "Threshold = 0\n"
	}

	id := cmn.RandStr(6)
	cfgstr := strings.Join([]string{string(`
[Server]
`),
		fmt.Sprintf("Identifier = \"%v\"\n", id),
		string(`MaximumAttributes = 5
IsProvider = true
`),
		fmt.Sprintf("DataDir = \"%v\"\n", filepath.Join(tmpDir, "provider", id)),
		fmt.Sprintf("Addresses = [\"%v\"]\n", addr),
		fmt.Sprintf("BlockchainNodeAddresses = [ \"127.0.0.1:%v\" ]\n", tendermintRPCPort),
		fmt.Sprintf("GRPCAddresses = [\"%v\"]\n", grpcaddr),
		"[Provider]\n",
		thresholdStr,
		IAAddressesStr,
		// while BlockchainKeysFile do not matter much here, it will be needed for nym-related tests, so TODO:
		string(`
BlockchainKeysFile = "/tmp/foo.json"
[Logging]
Disable = true
Level = "NOTICE"
[Debug]
`),
		fmt.Sprintf("DisableAllBlockchainCommunication = %v\n", true),
		fmt.Sprintf("ProviderStartupTimeout = %v\n", providerStartupTimeout),
		fmt.Sprintf("ProviderStartupRetryInterval = %v\n", providerStartupRetryInterval),
		fmt.Sprintf("ConnectionTimeout = %v\n", connectionTimeout)}, "")

	cfg, err := config.LoadBinary([]byte(cfgstr))
	if err != nil {
		log.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return srv
}

func startIssuer(n int, addr string, grpcaddr string, tmpDir string) *Server {
	id := cmn.RandStr(6)
	cfgstr := strings.Join([]string{string(`
[Server]
`),
		fmt.Sprintf("Identifier = \"%v\"\n", id),
		string(`MaximumAttributes = 5
		IsIssuer = true
		`),
		fmt.Sprintf("DataDir = \"%v\"\n", filepath.Join(tmpDir, "issuer", id)),
		fmt.Sprintf("Addresses = [\"%v\"]\n", addr),
		fmt.Sprintf("GRPCAddresses = [\"%v\"]\n", grpcaddr),
		fmt.Sprintf("BlockchainNodeAddresses = [ \"127.0.0.1:%v\" ]\n", tendermintRPCPort),
		string(`
		[Issuer]
		`),
		fmt.Sprintf("ID = %v\n", n+1),
		fmt.Sprintf("VerificationKeyFile = \"%v/verification%v-n=5-t=3.pem\"\n", issuersKeysFolder, n),
		fmt.Sprintf("SecretKeyFile = \"%v/secret%v-n=5-t=3.pem\"\n", issuersKeysFolder, n)}, "")
	cfgstr += string(`
			[Logging]
			Disable = true
			Level = "NOTICE"
			`)
	cfgstr += fmt.Sprintf("[Debug]\nDisableAllBlockchainCommunication = %v\n", true)

	cfg, err := config.LoadBinary([]byte(cfgstr))
	if err != nil {
		log.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return srv
}

func startAllIssuers(tmpDir string) {
	// todo: does it get wd relative to this file or where test command was run?
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	issuersKeysFolder = path.Join(dir, issuersKeysFolderRelative)
	issuers = make([]*Server, 0, 5)

	for i := range issuerTCPAddresses {
		issuers = append(issuers, startIssuer(i, issuerTCPAddresses[i], issuerGRPCAddresses[i], tmpDir))
	}
}

// required by some tests
func stopAllIssuers() {
	for _, srv := range issuers {
		srv.Shutdown()
	}
}

func TestGetIAsVerificationKeys(t *testing.T) {
	for _, provider := range []*providerServer{nonThresholdProvider, thresholdProvider} {
		// firstly turn off all issuers and check if timeout occurs
		stopAllIssuers()

		// no issuer active
		vks, pp, err := provider.server.getIAsVerificationKeys()
		assert.Nil(t, vks)
		assert.Nil(t, pp)
		assert.EqualError(t, err, "Startup timeout")

		// 'broken' issuers active (less than threshold); we want to make sure server doesn't crash on garbage response
		dummy1 := dummyServer([]byte("foo"), issuerTCPAddresses[0])
		dummy2 := dummyServer(nil, issuerTCPAddresses[1])

		vks, pp, err = provider.server.getIAsVerificationKeys()
		assert.Nil(t, vks)
		assert.Nil(t, pp)
		assert.EqualError(t, err, "Startup timeout")

		dummy1.Close()
		dummy2.Close()

		// doesn't matter that we're using different tmpDir as long as we clean afterwards
		tmpDir, err := ioutil.TempDir("", fmt.Sprintf("test-issuers-%v", cmn.RandStr(6)))
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		// start up less than threshold number of 'proper' issuers
		issuers[0] = startIssuer(0, issuerTCPAddresses[0], issuerGRPCAddresses[0], filepath.Join(tmpDir, "0"))
		issuers[1] = startIssuer(1, issuerTCPAddresses[1], issuerGRPCAddresses[1], filepath.Join(tmpDir, "1"))

		vks, pp, err = provider.server.getIAsVerificationKeys()
		assert.Nil(t, vks)
		assert.Nil(t, pp)
		assert.EqualError(t, err, "Startup timeout")

		// start's up 3rd - threshold - issuer
		issuers[2] = startIssuer(2, issuerTCPAddresses[2], issuerGRPCAddresses[2], filepath.Join(tmpDir, "2"))

		if strings.Compare(provider.tcpaddress, providerTCPAddresses[0]) == 0 { // if it's non-threshold we ignore this case
			vks, pp, err = provider.server.getIAsVerificationKeys()
			// fmt.Println(vks)
			assert.Len(t, vks, 3)
			// fmt.Println(pp)

			assert.Len(t, pp.Xs(), 3)
			// fmt.Println(err)

			assert.Nil(t, err)
		}

		// restart rest of issuers
		issuers[3] = startIssuer(3, issuerTCPAddresses[3], issuerGRPCAddresses[3], filepath.Join(tmpDir, "3"))
		issuers[4] = startIssuer(4, issuerTCPAddresses[4], issuerGRPCAddresses[4], filepath.Join(tmpDir, "4"))

		vks, pp, err = provider.server.getIAsVerificationKeys()
		assert.True(t, len(vks) >= thresholdVal)
		if strings.Compare(provider.tcpaddress, providerTCPAddresses[0]) == 0 {
			assert.True(t, len(pp.Xs()) >= thresholdVal)
		}
		assert.Nil(t, err)

		// replace one issuer with an invalid one
		issuers[4].Shutdown()
		dummy := dummyServer([]byte("foo"), issuerTCPAddresses[4])

		// should fail for non-threshold (we require ALL IAs to be valid)

		if strings.Compare(provider.tcpaddress, providerTCPAddresses[0]) == 0 {
			vks, pp, err = provider.server.getIAsVerificationKeys()
			assert.True(t, len(vks) >= thresholdVal)
			assert.True(t, len(pp.Xs()) >= thresholdVal)
			assert.Nil(t, err)
		} else {
			vks, pp, err = provider.server.getIAsVerificationKeys()
			assert.Nil(t, vks)
			assert.Nil(t, pp)
			assert.EqualError(t, err, "Startup timeout")
		}
		dummy.Close()
	}
}

// it is sufficient to test arbitrary malformed requests as all valid cases and valid querys with invalid attributes
// were tested by client_test.go
func TestIssuer(t *testing.T) {
	// doesn't matter that we're using different tmpDir as long as we clean afterwards
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("test-issuers-%v", cmn.RandStr(6)))
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	stopAllIssuers() // to ensure all addresses are available
	startIssuer(1, issuerTCPAddresses[1], issuerGRPCAddresses[1], filepath.Join(tmpDir, "1"))

	testAddressTCP := issuerTCPAddresses[1]
	testAddressGRPC := issuerGRPCAddresses[1]

	connTCP, err := net.Dial("tcp", testAddressTCP)
	assert.Nil(t, err)

	connGRPC, err := net.Dial("tcp", testAddressGRPC)
	assert.Nil(t, err)

	garbageBytes := [][]byte{
		{},
		nil,
		[]byte("foo"),
		make([]byte, 100000),
	}

	for _, b := range garbageBytes {
		// we try to write them
		if _, werr := connTCP.Write(b); werr != nil {
			t.Logf("Failed to write to connection: %v", werr)
		}

		// and check if the server is still running afterwards
		_, err = net.DialTimeout("tcp", testAddressTCP, time.Millisecond*500)
		assert.Nil(t, err)

		if _, werr := connGRPC.Write(b); werr != nil {
			t.Logf("Failed to write to connection: %v", werr)
		}
		_, err = net.DialTimeout("tcp", testAddressGRPC, time.Millisecond*500)
		assert.Nil(t, err)
	}
}

func TestMain(m *testing.M) {
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("test-issuers-%v", cmn.RandStr(6)))
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	node, err := testnode.CreateTestingNymNode(tmpDir, tendermintRPCPort-1)
	if err != nil {
		log.Fatal(err)
	}
	if err := node.Start(); err != nil {
		log.Fatal(err)
	}

	startAllIssuers(tmpDir)

	thresholdProviderServer := startProvider(providerTCPAddresses[0], providerGRPCAddresses[0], true, tmpDir)
	thresholdProvider = &providerServer{
		server:      thresholdProviderServer,
		grpcaddress: providerGRPCAddresses[0],
		tcpaddress:  providerTCPAddresses[0],
	}

	nonThresholdProviderServer := startProvider(providerTCPAddresses[1], providerGRPCAddresses[1], false, tmpDir)
	nonThresholdProvider = &providerServer{
		server:      nonThresholdProviderServer,
		grpcaddress: providerGRPCAddresses[1],
		tcpaddress:  providerTCPAddresses[1],
	}

	runTests := m.Run()

	// cleanly shutdown the servers
	for _, srv := range issuers {
		srv.Shutdown()
	}

	thresholdProvider.server.Shutdown()
	nonThresholdProvider.server.Shutdown()

	node.Stop()
	os.RemoveAll(tmpDir)

	os.Exit(runTests)
}
