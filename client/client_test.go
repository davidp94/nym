// client_test.go - tests for coconut client API
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

// This package only cares about client handling of requests,
// tests for servers, services, etc will be in separate files.
// It is assumed that servers work correctly.
package client

import (
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/logger"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"

	"0xacab.org/jstuczyn/CoconutGo/server/commands"

	cconfig "0xacab.org/jstuczyn/CoconutGo/client/config"
	"0xacab.org/jstuczyn/CoconutGo/server"
	sconfig "0xacab.org/jstuczyn/CoconutGo/server/config"
	"github.com/stretchr/testify/assert"
)

const issuersKeysFolderRelative = "../testdata/issuerkeys"
const clientKeysFolderRelative = "../testdata/clientkeys"

var issuersKeysFolder string
var issuers []*server.Server
var providers []*server.Server
var issuerTCPAddresses = []string{
	"127.0.0.1:4100",
	"127.0.0.1:4101",
	"127.0.0.1:4102",
	"127.0.0.1:4103",
	"127.0.0.1:4104",
}
var issuerGRPCAddresses = []string{
	"127.0.0.1:4200",
	"127.0.0.1:4201",
	"127.0.0.1:4202",
	"127.0.0.1:4203",
	"127.0.0.1:4204",
}
var providerTCPAddresses = []string{
	"127.0.0.1:5100",
	"127.0.0.1:5101",
}
var providerGRPCAddresses = []string{
	"127.0.0.1:5200",
	"127.0.0.1:5201",
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

func startProvider(n int, addr string, grpcaddr string) *server.Server {
	IAAddressesStr := makeStringOfAddresses("IAAddresses", issuerTCPAddresses)

	cfgstr := strings.Join([]string{string(`
		[Server]
		IsProvider = true
		`),
		fmt.Sprintf("Addresses = [\"%v\"]\n", addr),
		fmt.Sprintf("GRPCAddresses = [\"%v\"]\n", grpcaddr),
		string(`
		[Provider]
		Threshold = 3
		`),
		IAAddressesStr,
		string(`
		[Logging]
		Disable = true
		Level = "DEBUG"
		`)}, "")

	cfg, err := sconfig.LoadBinary([]byte(cfgstr))
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return srv
}

func startIssuer(n int, addr string, grpcaddr string) *server.Server {
	cfgstr := strings.Join([]string{string(`
		[Server]
		IsIssuer = true
		`),
		fmt.Sprintf("Addresses = [\"%v\"]\n", addr),
		fmt.Sprintf("GRPCAddresses = [\"%v\"]\n", grpcaddr),
		string(`
		[Issuer]
		MaximumAttributes = 5
		`),
		fmt.Sprintf("VerificationKeyFile = \"%v/verification%v-n=5-t=3.pem\"\n", issuersKeysFolder, n),
		fmt.Sprintf("SecretKeyFile = \"%v/secret%v-n=5-t=3.pem\"\n", issuersKeysFolder, n),
		string(`
		[Logging]
		Disable = true
		Level = "Notice"
		`)}, "")

	cfg, err := sconfig.LoadBinary([]byte(cfgstr))
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return srv
}

func init() {
	// todo: does it get wd relative to this file or where test command was run?
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	issuersKeysFolder = path.Join(dir, issuersKeysFolderRelative)
	issuers = make([]*server.Server, 0, 5)
	providers = make([]*server.Server, 0, 2)

	// for i := range issuerTCPAddresses {
	// 	issuers = append(issuers, startIssuer(i, issuerTCPAddresses[i], issuerGRPCAddresses[i]))
	// }

	// for i := range providerTCPAddresses {
	// 	providers = append(providers, startProvider(i, providerTCPAddresses[i], providerGRPCAddresses[i]))
	// }

	// time.Sleep(5 * time.Second)
	// for _, srv := range issuers {
	// 	srv.Shutdown()
	// }

	// for _, srv := range providers {
	// 	srv.Shutdown()
	// }
}

// if len(gRCPAddr) > 0 it means the client will use gRPC for comm
func createBasicClientCfgStr(tcpAddrs []string, gRCPAddr []string) string {
	cfgStr := "[Client]\n"
	if len(gRCPAddr) > 0 {
		cfgStr += "UseGRPC = true\n"
		cfgStr += makeStringOfAddresses("IAgRPCAddresses", tcpAddrs)
		cfgStr += "\n"
	} else {
		cfgStr += "UseGRPC = false\n"
		cfgStr += makeStringOfAddresses("IAAddresses", tcpAddrs)
		cfgStr += "\n"
	}

	return cfgStr
}

func aa() *cconfig.Config {
	return nil
}

func TestParseVkResponse(t *testing.T) {
	// valid vk, valid status
	// valid vk, invalid status
	// invalid vk, valid status
	// parts being nil

	validStatus := &commands.Status{
		Code:    int32(commands.StatusCode_OK),
		Message: "",
	}

	// for this test, we don't need any client properties
	// only logger to not crash by trying to call object that doesn't exist
	emptyClient := &Client{log: logger.New("", "DEBUG", true).GetLogger("Client")}

	// completely valid responses with variable size keys
	for _, i := range []int{1, 3, 5, 10} {
		params, err := coconut.Setup(i)
		assert.Nil(t, err)

		_, validVk, err := coconut.Keygen(params)
		assert.Nil(t, err)

		validVkProto, err := validVk.ToProto()
		assert.Nil(t, err)

		validResponse := &commands.VerificationKeyResponse{
			Vk:     validVkProto,
			Status: validStatus,
		}

		parsedVk, err := emptyClient.parseVkResponse(validResponse)
		assert.Nil(t, err)

		// check we actually got the same key
		assert.True(t, validVk.G2().Equals(parsedVk.G2()))
		assert.True(t, validVk.Alpha().Equals(parsedVk.Alpha()))
		assert.Len(t, validVk.Beta(), len(parsedVk.Beta()))
		for i := range validVk.Beta() {
			assert.True(t, validVk.Beta()[i].Equals(parsedVk.Beta()[i]))
		}
	}

	failedCodes := []commands.StatusCode{
		commands.StatusCode_UNKNOWN,
		commands.StatusCode_INVALID_COMMAND,
		commands.StatusCode_INVALID_ARGUMENTS,
		commands.StatusCode_PROCESSING_ERROR,
		commands.StatusCode_NOT_IMPLEMENTED,
		commands.StatusCode_REQUEST_TIMEOUT,
		commands.StatusCode_UNAVAILABLE,
	}

	// valid keys with failed status
	for _, code := range failedCodes {
		invalidStatus := &commands.Status{
			Code:    int32(code),
			Message: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		}

		params, err := coconut.Setup(5)
		assert.Nil(t, err)

		_, validVk, err := coconut.Keygen(params)
		assert.Nil(t, err)

		validVkProto, err := validVk.ToProto()
		assert.Nil(t, err)

		response := &commands.VerificationKeyResponse{
			Vk:     validVkProto,
			Status: invalidStatus,
		}

		vk, err := emptyClient.parseVkResponse(response)
		assert.Nil(t, vk)
		assert.Error(t, err)
	}

	// longer than ECP2 len (4*MB)
	longb := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla non mollis sapien, sed volutpat nisl. Duis faucibus, est at accumsan tincidunt, enim sapien pharetra justo, at sollicitudin libero massa id lectus. Aenean ac nulla risus. Duis ullamcorper turpis nulla, sit amet finibus augue posuere ac.")

	invalidBytes := [][]byte{
		nil,
		[]byte{},
		[]byte{1, 2, 3},
		longb,
	}

	// invalid keys with valid status (server thinks it all went fine)
	for _, invalidByte := range invalidBytes {
		invalidVk1 := &coconut.ProtoVerificationKey{G2: invalidByte}
		invalidVk2 := &coconut.ProtoVerificationKey{Alpha: invalidByte}
		invalidVk3 := &coconut.ProtoVerificationKey{Beta: [][]byte{
			invalidByte,
			invalidByte,
			invalidByte,
		}}

		invalidVk4 := &coconut.ProtoVerificationKey{
			G2:    invalidByte,
			Alpha: invalidByte,
			Beta: [][]byte{
				invalidByte,
				invalidByte,
				invalidByte,
			},
		}

		// just a single 'corrupted' element:
		params, err := coconut.Setup(5)
		assert.Nil(t, err)

		_, validVk, err := coconut.Keygen(params)
		assert.Nil(t, err)

		invalidVk5, err := validVk.ToProto()
		assert.Nil(t, err)
		invalidVk5.G2 = invalidByte

		invalidVk6, err := validVk.ToProto()
		assert.Nil(t, err)
		invalidVk6.Alpha = invalidByte

		invalidVk7, err := validVk.ToProto()
		assert.Nil(t, err)
		invalidVk7.Beta = [][]byte{
			invalidByte,
			invalidByte,
			invalidByte,
		}

		invalidVks := []*coconut.ProtoVerificationKey{
			invalidVk1,
			invalidVk2,
			invalidVk3,
			invalidVk4,
			invalidVk5,
			invalidVk6,
			invalidVk7,
		}

		for _, invVk := range invalidVks {
			response := &commands.VerificationKeyResponse{
				Vk:     invVk,
				Status: validStatus,
			}

			vk, err := emptyClient.parseVkResponse(response)
			assert.Nil(t, vk)
			assert.Error(t, err)
		}
	}

	// additional cases not covered by the loop:
	invalidVk1 := &coconut.ProtoVerificationKey{} // all zeroed fields
	invalidVk2 := &coconut.ProtoVerificationKey{Beta: nil}

	invalidVks := []*coconut.ProtoVerificationKey{
		invalidVk1,
		invalidVk2,
	}

	for _, invVk := range invalidVks {
		response := &commands.VerificationKeyResponse{
			Vk:     invVk,
			Status: validStatus,
		}

		vk, err := emptyClient.parseVkResponse(response)
		assert.Nil(t, vk)
		assert.Error(t, err)
	}

	// nil proto, nil status
	vk, err := emptyClient.parseVkResponse(nil)
	assert.Nil(t, vk)
	assert.Error(t, err)

	response := &commands.VerificationKeyResponse{
		Vk:     nil,
		Status: validStatus,
	}
	vk, err = emptyClient.parseVkResponse(response)
	assert.Nil(t, vk)
	assert.Error(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)
	_, validVk, err := coconut.Keygen(params)
	assert.Nil(t, err)
	validVkProto, err := validVk.ToProto()
	assert.Nil(t, err)

	response = &commands.VerificationKeyResponse{
		Vk:     validVkProto,
		Status: nil,
	}
	vk, err = emptyClient.parseVkResponse(response)
	assert.Nil(t, vk)
	assert.Error(t, err)
}
