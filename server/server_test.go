// server_test.go - tests for coconut server API
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
package server

// TODO: SENDING GRPC PACKET (OR PROBABLY JUST AN INVALID ONE) TO A TCP PORT
// CAUSES SERVER TO RUN OUT OF MEMORY -> ReadPacketFromConn FAILS

import (
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/server/config"
)

const issuersKeysFolderRelative = "../testdata/issuerkeys"
const thresholdVal = 3 // defined by the pre-generated keys
var issuersKeysFolder string
var issuers []*Server

var issuerTCPAddresses = []string{
	"127.0.0.1:4100",
	"127.0.0.1:4101",
	"127.0.0.1:4102",
	"127.0.0.1:4103",
	"127.0.0.1:4104",
}

func startIssuer(n int, addr string) *Server {
	cfgstr := strings.Join([]string{string(`
		[Server]
		MaximumAttributes = 5
		IsIssuer = true
		`),
		fmt.Sprintf("Addresses = [\"%v\"]\n", addr),
		string(`
		[Issuer]
		`),
		fmt.Sprintf("VerificationKeyFile = \"%v/verification%v-n=5-t=3.pem\"\n", issuersKeysFolder, n),
		fmt.Sprintf("SecretKeyFile = \"%v/secret%v-n=5-t=3.pem\"\n", issuersKeysFolder, n),
		string(`
		[Logging]
		Disable = true
		Level = "Notice"
		`)}, "")

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

func startAllIssuers() {
	// todo: does it get wd relative to this file or where test command was run?
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	issuersKeysFolder = path.Join(dir, issuersKeysFolderRelative)
	issuers = make([]*Server, 0, 5)

	for i := range issuerTCPAddresses {
		issuers = append(issuers, startIssuer(i, issuerTCPAddresses[i]))
	}
}

func TestProviderStartup(t *testing.T) {

}
