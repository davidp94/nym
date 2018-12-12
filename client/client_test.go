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
	"sync"
	"testing"

	cconfig "0xacab.org/jstuczyn/CoconutGo/client/config"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server"
	"0xacab.org/jstuczyn/CoconutGo/server/comm/utils"
	"0xacab.org/jstuczyn/CoconutGo/server/commands"
	sconfig "0xacab.org/jstuczyn/CoconutGo/server/config"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

type providerServer struct {
	tcpaddress  string
	grpcaddress string
	server      *server.Server
}

const issuersKeysFolderRelative = "../testdata/issuerkeys"
const clientKeysFolderRelative = "../testdata/clientkeys"
const thresholdVal = 3 // defined by the pre-generated keys

var issuersKeysFolder string
var issuers []*server.Server
var thresholdProvider *providerServer
var nonThresholdProvider *providerServer

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
	"127.0.0.1:5200", // threshold
	"127.0.0.1:5201", // nonthreshold
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

func startProvider(addr string, grpcaddr string, threshold bool) *server.Server {
	IAAddressesStr := makeStringOfAddresses("IAAddresses", issuerTCPAddresses)
	thresholdStr := ""
	if threshold {
		thresholdStr = fmt.Sprintf("Threshold = %v\n", thresholdVal)
	} else {
		thresholdStr = "Threshold = 0\n"
	}

	cfgstr := strings.Join([]string{string(`
[Server]
MaximumAttributes = 5
IsProvider = true
`),
		fmt.Sprintf("Addresses = [\"%v\"]\n", addr),
		fmt.Sprintf("GRPCAddresses = [\"%v\"]\n", grpcaddr),
		"[Provider]\n",
		thresholdStr,
		IAAddressesStr,
		string(`
[Logging]
Disable = true
Level = "NOTICE"
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
		MaximumAttributes = 5
		IsIssuer = true
		`),
		fmt.Sprintf("Addresses = [\"%v\"]\n", addr),
		fmt.Sprintf("GRPCAddresses = [\"%v\"]\n", grpcaddr),
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

	for i := range issuerTCPAddresses {
		issuers = append(issuers, startIssuer(i, issuerTCPAddresses[i], issuerGRPCAddresses[i]))
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// since they need to get their aggregate key (+ need to fix initial wait time), it takes a while to start them up
	// and we can start those together
	go func() {
		thresholdProviderServer := startProvider(providerTCPAddresses[0], providerGRPCAddresses[0], true)
		thresholdProvider = &providerServer{
			server:      thresholdProviderServer,
			grpcaddress: providerGRPCAddresses[0],
			tcpaddress:  providerTCPAddresses[0],
		}
		wg.Done()
	}()
	go func() {
		nonThresholdProviderServer := startProvider(providerTCPAddresses[1], providerGRPCAddresses[1], false)
		nonThresholdProvider = &providerServer{
			server:      nonThresholdProviderServer,
			grpcaddress: providerGRPCAddresses[1],
			tcpaddress:  providerTCPAddresses[1],
		}
		wg.Done()
	}()

	wg.Wait()

	// time.Sleep(5 * time.Second)
	// for _, srv := range issuers {
	// 	srv.Shutdown()
	// }

	// thresholdProvider.Shutdown()
	// nonThresholdProvider.Shutdown()
}

// if len(gRCPAddr) > 0 it means the client will use gRPC for comm
func createBasicClientCfgStr(tcpAddrs []string, gRCPAddr []string) string {
	cfgStr := "[Client]\n"
	if len(gRCPAddr) > 0 {
		cfgStr += "UseGRPC = true\n"
		cfgStr += makeStringOfAddresses("IAgRPCAddresses", gRCPAddr)
		cfgStr += "\n"
	} else {
		cfgStr += "UseGRPC = false\n"
		cfgStr += makeStringOfAddresses("IAAddresses", tcpAddrs)
		cfgStr += "\n"
	}

	return cfgStr
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
		assert.NotNil(t, parsedVk)
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

func getRandomAttributes(G *bpgroup.BpGroup, n int) []*Curve.BIG {
	attrs := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		attrs[i] = Curve.Randomnum(G.Order(), G.Rng())
	}
	return attrs
}

func TestParseSignResponse(t *testing.T) {
	// valid sig, valid status
	// valid sig, invalid status
	// invalid sig, valid status
	// parts being nil

	validStatus := &commands.Status{
		Code:    int32(commands.StatusCode_OK),
		Message: "",
	}

	// for this test, we don't need any client properties
	// only logger to not crash by trying to call object that doesn't exist
	emptyClient := &Client{log: logger.New("", "DEBUG", true).GetLogger("Client")}

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	sk, _, err := coconut.Keygen(params)
	assert.Nil(t, err)

	// a completely valid sig
	validSig, err := coconut.Sign(params, sk, getRandomAttributes(params.G, 5))
	assert.Nil(t, err)

	validProtoSig, err := validSig.ToProto()
	assert.Nil(t, err)

	sig, err := emptyClient.parseSignResponse(&commands.SignResponse{
		Sig:    validProtoSig,
		Status: validStatus,
	})

	assert.NotNil(t, sig)
	assert.Nil(t, err)

	assert.True(t, validSig.Sig1().Equals(sig.Sig1()))
	assert.True(t, validSig.Sig2().Equals(sig.Sig2()))

	failedCodes := []commands.StatusCode{
		commands.StatusCode_UNKNOWN,
		commands.StatusCode_INVALID_COMMAND,
		commands.StatusCode_INVALID_ARGUMENTS,
		commands.StatusCode_PROCESSING_ERROR,
		commands.StatusCode_NOT_IMPLEMENTED,
		commands.StatusCode_REQUEST_TIMEOUT,
		commands.StatusCode_UNAVAILABLE,
	}

	// valid sigs with failed status
	for _, code := range failedCodes {
		invalidStatus := &commands.Status{
			Code:    int32(code),
			Message: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		}

		response := &commands.SignResponse{
			Sig:    validProtoSig,
			Status: invalidStatus,
		}

		sig, err := emptyClient.parseSignResponse(response)
		assert.Nil(t, sig)
		assert.Error(t, err)
	}

	// longer than ECP len (MB+1)
	longb := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla non mollis sapien, sed volutpat nisl. Duis faucibus, est at accumsan tincidunt, enim sapien pharetra justo, at sollicitudin libero massa id lectus. Aenean ac nulla risus. Duis ullamcorper turpis nulla, sit amet finibus augue posuere ac.")

	invalidBytes := [][]byte{
		nil,
		[]byte{},
		[]byte{1, 2, 3},
		longb,
	}

	// invalid sigs with valid status (server thinks it all went fine)
	for _, invalidByte := range invalidBytes {
		invalidSig1 := &coconut.ProtoSignature{Sig1: invalidByte}
		invalidSig2 := &coconut.ProtoSignature{Sig2: invalidByte}
		invalidSig3 := &coconut.ProtoSignature{Sig1: invalidByte, Sig2: invalidByte}

		invalidSig4, err := validSig.ToProto()
		assert.Nil(t, err)
		invalidSig4.Sig1 = invalidByte

		invalidSig5, err := validSig.ToProto()
		assert.Nil(t, err)
		invalidSig5.Sig2 = invalidByte

		invalidSigs := []*coconut.ProtoSignature{
			invalidSig1,
			invalidSig2,
			invalidSig3,
			invalidSig4,
			invalidSig5,
		}

		for _, invSig := range invalidSigs {
			response := &commands.SignResponse{
				Sig:    invSig,
				Status: validStatus,
			}

			sig, err := emptyClient.parseSignResponse(response)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}
	}

	// additional cases not covered by the loop:
	invalidSig1 := &coconut.ProtoSignature{} // all zeroed fields

	invalidSigs := []*coconut.ProtoSignature{
		invalidSig1,
	}

	for _, invSig := range invalidSigs {
		response := &commands.SignResponse{
			Sig:    invSig,
			Status: validStatus,
		}

		sig, err := emptyClient.parseSignResponse(response)
		assert.Nil(t, sig)
		assert.Error(t, err)
	}

	// nil proto, nil status
	sig, err = emptyClient.parseSignResponse(nil)
	assert.Nil(t, sig)
	assert.Error(t, err)

	response := &commands.SignResponse{
		Sig:    nil,
		Status: validStatus,
	}
	sig, err = emptyClient.parseSignResponse(response)
	assert.Nil(t, sig)
	assert.Error(t, err)

	response = &commands.SignResponse{
		Sig:    validProtoSig,
		Status: nil,
	}
	sig, err = emptyClient.parseSignResponse(response)
	assert.Nil(t, sig)
	assert.Error(t, err)
}

func TestParseBlindSignResponse(t *testing.T) {
	// valid sig, valid status
	// valid sig, invalid status
	// invalid sig, valid status
	// parts being nil

	validStatus := &commands.Status{
		Code:    int32(commands.StatusCode_OK),
		Message: "",
	}

	// those really don't matter at this point, but if they are invalid,
	// we won't be able to make a client
	cfgstr := createBasicClientCfgStr(issuerTCPAddresses, nil)
	cfgstr += string(`PersistentKeys = false

[Logging]
Disable = true
Level = "DEBUG"
		`)

	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)

	// this test requires a proper client since we need to actually assign work
	// to its cryptoworker
	client, err := New(cfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	sk, _, err := coconut.Keygen(params)
	assert.Nil(t, err)

	numAttrs := []struct {
		pub  int
		priv int
	}{
		{2, 3},
		{0, 5},
	}
	for _, numAttr := range numAttrs {
		pubM := getRandomAttributes(params.G, numAttr.pub)
		privM := getRandomAttributes(params.G, numAttr.priv)
		blindSignMats, err := coconut.PrepareBlindSign(params, client.elGamalPublicKey, pubM, privM)
		assert.Nil(t, err)

		validBlindSig, err := coconut.BlindSign(params, sk, blindSignMats, client.elGamalPublicKey, pubM)
		assert.Nil(t, err)

		unblindedValidBlindSig := coconut.Unblind(params, validBlindSig, client.elGamalPrivateKey)

		validProtoBlindSig, err := validBlindSig.ToProto()
		assert.Nil(t, err)

		response := &commands.BlindSignResponse{
			Sig:    validProtoBlindSig,
			Status: validStatus,
		}

		sig, err := client.parseBlindSignResponse(response)
		assert.NotNil(t, sig)
		assert.Nil(t, err)

		assert.True(t, unblindedValidBlindSig.Sig1().Equals(sig.Sig1()))
		assert.True(t, unblindedValidBlindSig.Sig2().Equals(sig.Sig2()))

		failedCodes := []commands.StatusCode{
			commands.StatusCode_UNKNOWN,
			commands.StatusCode_INVALID_COMMAND,
			commands.StatusCode_INVALID_ARGUMENTS,
			commands.StatusCode_PROCESSING_ERROR,
			commands.StatusCode_NOT_IMPLEMENTED,
			commands.StatusCode_REQUEST_TIMEOUT,
			commands.StatusCode_UNAVAILABLE,
		}

		// valid sigs with failed status
		for _, code := range failedCodes {
			invalidStatus := &commands.Status{
				Code:    int32(code),
				Message: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			}

			response = &commands.BlindSignResponse{
				Sig:    validProtoBlindSig,
				Status: invalidStatus,
			}

			sig, err := client.parseBlindSignResponse(response)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}

		// longer than ECP len (MB+1)
		longb := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla non mollis sapien, sed volutpat nisl. Duis faucibus, est at accumsan tincidunt, enim sapien pharetra justo, at sollicitudin libero massa id lectus. Aenean ac nulla risus. Duis ullamcorper turpis nulla, sit amet finibus augue posuere ac.")

		invalidBytes := [][]byte{
			nil,
			[]byte{},
			[]byte{1, 2, 3},
			longb,
		}

		// invalid sigs with valid status (server thinks it all went fine)
		for _, invalidByte := range invalidBytes {
			invalidBlindSig1 := &coconut.ProtoBlindedSignature{Sig1: invalidByte}
			invalidBlindSig2 := &coconut.ProtoBlindedSignature{Sig2Tilda: &elgamal.ProtoEncryption{
				C1: invalidByte,
				C2: invalidByte,
			}}

			invalidBlindSig3 := &coconut.ProtoBlindedSignature{
				Sig1: invalidByte,
				Sig2Tilda: &elgamal.ProtoEncryption{
					C1: invalidByte,
					C2: invalidByte,
				},
			}

			// just a single 'corrupted' element:
			invalidBlindSig4, err := validBlindSig.ToProto()
			assert.Nil(t, err)
			invalidBlindSig4.Sig1 = invalidByte

			invalidBlindSig5, err := validBlindSig.ToProto()
			assert.Nil(t, err)
			invalidBlindSig5.Sig2Tilda.C1 = invalidByte

			invalidBlindSig6, err := validBlindSig.ToProto()
			assert.Nil(t, err)
			invalidBlindSig6.Sig2Tilda.C2 = invalidByte

			invalidBlindSigs := []*coconut.ProtoBlindedSignature{
				invalidBlindSig1,
				invalidBlindSig2,
				invalidBlindSig3,
				invalidBlindSig4,
				invalidBlindSig5,
				invalidBlindSig6,
			}

			for _, invBlindSig := range invalidBlindSigs {
				response := &commands.BlindSignResponse{
					Sig:    invBlindSig,
					Status: validStatus,
				}

				sig, err := client.parseBlindSignResponse(response)
				assert.Nil(t, sig)
				assert.Error(t, err)
			}
		}

		// additional cases not covered by the loop:
		invalidBlindSig1 := &coconut.ProtoBlindedSignature{} // all zeroed fields
		invalidBlindSig2 := &coconut.ProtoBlindedSignature{Sig2Tilda: nil}

		invalidBlindSigs := []*coconut.ProtoBlindedSignature{
			invalidBlindSig1,
			invalidBlindSig2,
		}

		for _, invBlindSig := range invalidBlindSigs {
			response := &commands.BlindSignResponse{
				Sig:    invBlindSig,
				Status: validStatus,
			}

			sig, err := client.parseBlindSignResponse(response)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}

		// nil proto, nil status
		sig, err = client.parseBlindSignResponse(nil)
		assert.Nil(t, sig)
		assert.Error(t, err)

		response = &commands.BlindSignResponse{
			Sig:    nil,
			Status: validStatus,
		}
		sig, err = client.parseBlindSignResponse(response)
		assert.Nil(t, sig)
		assert.Error(t, err)

		response = &commands.BlindSignResponse{
			Sig:    validProtoBlindSig,
			Status: nil,
		}
		sig, err = client.parseBlindSignResponse(response)
		assert.Nil(t, sig)
		assert.Error(t, err)
	}
}

func makeValidSignServerResponse(t *testing.T, address string, id int, pubM []*Curve.BIG, mock bool) *utils.ServerResponse {
	if mock {
		params, err := coconut.Setup(5)
		assert.Nil(t, err)
		sk, _, err := coconut.Keygen(params)
		assert.Nil(t, err)
		sig, err := coconut.Sign(params, sk, pubM)
		assert.Nil(t, err)
		b, err := sig.MarshalBinary()
		assert.Nil(t, err)
		return &utils.ServerResponse{
			MarshaledData: b,
			ServerAddress: address,
			ServerID:      id,
		}
	}
	cmd, err := commands.NewSignRequest(pubM)
	assert.Nil(t, err)
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.SignID)
	assert.NotNil(t, packetBytes)

	return utils.GetServerResponses(
		packetBytes,
		16,
		logger.New("", "DEBUG", true).GetLogger("Foo"),
		2000,
		5000,
		[]string{address},
		[]int{id},
	)[0]

}

func makeValidBlindSignServerResponse(t *testing.T, address string, id int, pubM []*Curve.BIG, privM []*Curve.BIG, egPub *elgamal.PublicKey, mock bool) *utils.ServerResponse {
	params, err := coconut.Setup(5)
	assert.Nil(t, err)
	blindSignMats, err := coconut.PrepareBlindSign(params, egPub, pubM, privM)

	if mock {
		sk, _, err := coconut.Keygen(params)
		assert.Nil(t, err)
		blindSig, err := coconut.BlindSign(params, sk, blindSignMats, egPub, pubM)
		assert.Nil(t, err)
		b, err := blindSig.MarshalBinary()
		assert.Nil(t, err)
		return &utils.ServerResponse{
			MarshaledData: b,
			ServerAddress: address,
			ServerID:      id,
		}
	}
	cmd, err := commands.NewBlindSignRequest(blindSignMats, egPub, pubM)
	assert.Nil(t, err)
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.BlindSignID)
	assert.NotNil(t, packetBytes)

	return utils.GetServerResponses(
		packetBytes,
		16,
		logger.New("", "DEBUG", true).GetLogger("Foo"),
		2000,
		5000,
		[]string{address},
		[]int{id},
	)[0]
}

func makeValidVkServerResponse(t *testing.T, address string, id int, mock bool) *utils.ServerResponse {
	if mock {
		params, err := coconut.Setup(5)
		assert.Nil(t, err)
		_, vk, err := coconut.Keygen(params)
		assert.Nil(t, err)
		b, err := vk.MarshalBinary()
		assert.Nil(t, err)
		return &utils.ServerResponse{
			MarshaledData: b,
			ServerAddress: address,
			ServerID:      id,
		}
	}
	cmd, err := commands.NewVerificationKeyRequest()
	assert.Nil(t, err)
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.GetVerificationKeyID)
	assert.NotNil(t, packetBytes)

	return utils.GetServerResponses(
		packetBytes,
		16,
		logger.New("", "DEBUG", true).GetLogger("Foo"),
		2000,
		5000,
		[]string{address},
		[]int{id},
	)[0]
}

func TestParseSignatureServerResponses(t *testing.T) {
	cfgstr := createBasicClientCfgStr(issuerTCPAddresses, nil)
	cfgstr += string(`PersistentKeys = false

[Logging]
Disable = true
Level = "DEBUG"
		`)

	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)

	// this test requires a proper client since we need to actually assign work
	// to its cryptoworker
	client, err := New(cfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)
	pubM := getRandomAttributes(params.G, 3)
	privM := getRandomAttributes(params.G, 2)

	tests := []struct {
		isThreshold      bool
		isBlind          bool
		validResponses   int
		invalidResponses int
	}{
		{false, false, 5, 0},
		{false, true, 5, 0},
		{true, false, 5, 0},
		{true, true, 5, 0},

		{false, false, 2, 0},
		{false, true, 2, 0},
		{true, false, 2, 0},
		{true, true, 2, 0},

		{false, false, 2, 1},
		{false, true, 2, 1},
		{true, false, 2, 1},
		{true, true, 2, 1},

		{false, false, 0, 5},
		{false, true, 0, 5},
		{true, false, 0, 5},
		{true, true, 0, 5},
	}

	invalidResponses := make([]*utils.ServerResponse, 0, 10)

	invalidResponses = append(
		invalidResponses,
		nil,
		makeValidVkServerResponse(t, "127.0.0.1:1234", 1, true),
		&utils.ServerResponse{},
		&utils.ServerResponse{MarshaledData: nil, ServerAddress: "127.0.0.1:1234", ServerID: 1},
		&utils.ServerResponse{MarshaledData: []byte{1, 2, 3}, ServerAddress: "127.0.0.1:1234", ServerID: 1},

		// + malformed marshaleddata in different ways
	)

	for _, test := range tests {
		responsesMock := make([]*utils.ServerResponse, 0, test.invalidResponses+test.validResponses)
		// nil responses
		sigs, pp := client.parseSignatureServerResponses(nil, test.isThreshold, test.isBlind)
		assert.Nil(t, sigs)
		assert.Nil(t, pp)

		for i := 0; i < test.validResponses; i++ {
			if test.isBlind {
				responsesMock = append(responsesMock, makeValidBlindSignServerResponse(t, issuerTCPAddresses[i], i+1, pubM, privM, client.elGamalPublicKey, false))
			} else {
				responsesMock = append(responsesMock, makeValidSignServerResponse(t, issuerTCPAddresses[i], i+1, pubM, false))
			}
		}

		// now include additional invalid responses to loop through
		// todo: more cases?
		invalidResponsesIn := invalidResponses
		if test.isBlind {
			sampleValid := makeValidBlindSignServerResponse(t, issuerTCPAddresses[0], 1, pubM, privM, client.elGamalPublicKey, false)
			invalidResponsesIn = append(invalidResponsesIn, &utils.ServerResponse{MarshaledData: sampleValid.MarshaledData, ServerAddress: sampleValid.ServerAddress})
			invalidResponsesIn = append(invalidResponsesIn, makeValidSignServerResponse(t, issuerTCPAddresses[0], 1, pubM, false))
		} else {
			sampleValid := makeValidSignServerResponse(t, issuerTCPAddresses[0], 1, pubM, false)
			invalidResponsesIn = append(invalidResponsesIn, &utils.ServerResponse{MarshaledData: sampleValid.MarshaledData, ServerAddress: sampleValid.ServerAddress})
			invalidResponsesIn = append(invalidResponsesIn, makeValidBlindSignServerResponse(t, issuerTCPAddresses[0], 1, pubM, privM, client.elGamalPublicKey, false))
		}

		for _, invResp := range invalidResponsesIn {
			responsesMockIn := responsesMock
			for i := 0; i < test.invalidResponses; i++ {
				responsesMockIn = append(responsesMockIn, invResp)
			}

			sigs, pp := client.parseSignatureServerResponses(responsesMockIn, test.isThreshold, test.isBlind)

			if test.isThreshold {
				assert.True(t, len(sigs) == len(pp.Xs()))
				assert.Len(t, sigs, test.validResponses)

			} else {
				if test.invalidResponses > 0 {
					assert.Nil(t, sigs)
				} else {
					assert.Len(t, sigs, test.validResponses)
				}

				assert.Nil(t, pp)
			}
		}
	}
}

func getNSigPP(t *testing.T, n int) ([]*coconut.Signature, *coconut.PolynomialPoints) {
	params, err := coconut.Setup(5)
	assert.Nil(t, err)
	pubM := getRandomAttributes(params.G, 5)
	sk, _, err := coconut.Keygen(params)
	assert.Nil(t, err)
	sigs := make([]*coconut.Signature, n)
	xs := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		sig, err := coconut.Sign(params, sk, pubM)
		assert.Nil(t, err)
		sigs[i] = sig
		xs[i] = Curve.NewBIGint(i + 1)
	}
	return sigs, coconut.NewPP(xs)
}

func getNVkPP(t *testing.T, n int) ([]*coconut.VerificationKey, *coconut.PolynomialPoints) {
	params, err := coconut.Setup(5)
	assert.Nil(t, err)
	// if used in non-threshold system, those keys do not behave 'differently' there compared to regular keys
	var vks []*coconut.VerificationKey
	if n < thresholdVal {
		vks = make([]*coconut.VerificationKey, n)
		for i := 0; i < n; i++ {
			_, vks[i], err = coconut.Keygen(params)
			assert.Nil(t, err)
		}
	} else {
		_, vks, err = coconut.TTPKeygen(params, thresholdVal, n)
		assert.Nil(t, err)
	}
	xs := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		xs[i] = Curve.NewBIGint(i + 1)
	}
	return vks, coconut.NewPP(xs)
}

func TestHandleReceivedSignatures(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)

	cfgStrTCP := createBasicClientCfgStr(issuerTCPAddresses, nil)
	cfgStrGRCP := createBasicClientCfgStr(nil, issuerGRPCAddresses)

	nonThrCfgStrTCP := cfgStrTCP + logStr
	nonThrCfgStrGRCP := cfgStrGRCP + logStr
	thrCfgStrTCP := cfgStrTCP + fmt.Sprintf("Threshold = %v\n", thresholdVal) + logStr
	thrCfgStrGRCP := cfgStrGRCP + fmt.Sprintf("Threshold = %v\n", thresholdVal) + logStr

	nonThresholdCfgTCP, err := cconfig.LoadBinary([]byte(nonThrCfgStrTCP))
	assert.Nil(t, err)
	nonThrClientTCP, err := New(nonThresholdCfgTCP)
	assert.Nil(t, err)

	nonThresholdCfgGRCP, err := cconfig.LoadBinary([]byte(nonThrCfgStrGRCP))
	assert.Nil(t, err)
	nonThrClientGRCP, err := New(nonThresholdCfgGRCP)
	assert.Nil(t, err)

	thresholdCfgTCP, err := cconfig.LoadBinary([]byte(thrCfgStrTCP))
	assert.Nil(t, err)
	thrClientTCP, err := New(thresholdCfgTCP)
	assert.Nil(t, err)

	thresholdCfgGRCP, err := cconfig.LoadBinary([]byte(thrCfgStrGRCP))
	assert.Nil(t, err)
	thrClientGRCP, err := New(thresholdCfgGRCP)
	assert.Nil(t, err)

	// since this method does not care if those are correct threshold credentials
	// (because there is no way to verify it without verification keys), we can obtain any set of signatures for testing
	validThrSigs, validThrPP := getNSigPP(t, thresholdVal)
	fullValidSigs, fullValidPP := getNSigPP(t, len(issuerTCPAddresses))

	for _, client := range []*Client{nonThrClientTCP, nonThrClientGRCP, thrClientTCP, thrClientGRCP} {
		sig, err := client.handleReceivedSignatures(nil, nil)
		assert.Nil(t, sig)
		assert.Error(t, err)

		sig, err = client.handleReceivedSignatures(nil, fullValidPP)
		assert.Nil(t, sig)
		assert.Error(t, err)

		sig, err = client.handleReceivedSignatures(fullValidSigs, nil)
		if client.cfg.Client.Threshold == 0 {
			assert.NotNil(t, sig)
			assert.Nil(t, err)
		} else {
			assert.Nil(t, sig)
			assert.Error(t, err)

			// inconsistent lengths check
			sig, err = client.handleReceivedSignatures(fullValidSigs[1:], fullValidPP)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}

		sig, err = client.handleReceivedSignatures(fullValidSigs, validThrPP)
		assert.Nil(t, sig)
		assert.Error(t, err)

		sig, err = client.handleReceivedSignatures(validThrSigs, fullValidPP)
		assert.Nil(t, sig)
		assert.Error(t, err)

		oldXs := fullValidPP.Xs()
		fullValidPP.Xs()[0] = fullValidPP.Xs()[2]
		sig, err = client.handleReceivedSignatures(fullValidSigs, fullValidPP)
		assert.Nil(t, sig)
		assert.Error(t, err)
		fullValidPP = coconut.NewPP(oldXs)

		invalidSigs := []*coconut.Signature{
			nil,
			&coconut.Signature{},
			coconut.NewSignature(validThrSigs[0].Sig1(), nil),
			coconut.NewSignature(nil, validThrSigs[0].Sig2()),
		}

		oldSigs := validThrSigs
		for _, invSig := range invalidSigs {
			validThrSigs[0] = invSig
			// ensures the invalid entry gets removed and threshold check fails
			if client.cfg.Client.Threshold > 0 {
				sig, err = client.handleReceivedSignatures(validThrSigs, validThrPP)
				assert.Nil(t, sig)
				assert.Error(t, err)

				sig, err = client.handleReceivedSignatures(validThrSigs, nil)
				assert.Nil(t, sig)
				assert.Error(t, err)
			}
		}
		validThrSigs = oldSigs
	}
}

func TestSignAttributesGrpc(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)
	cfgstr := createBasicClientCfgStr(nil, issuerGRPCAddresses)
	cfgstr += logStr
	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)
	client, err := New(cfg)
	assert.Nil(t, err)

	tcpcfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(issuerTCPAddresses, nil) + logStr))
	tcpclient, err := New(tcpcfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	// will be used for verification
	// tests for below method are separated.
	vk, err := client.GetAggregateVerificationKeyGrpc()
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPubMs[2], nil),
	}

	for _, validPubM := range validPubMs {
		sig, err := tcpclient.SignAttributesGrpc(validPubM)
		assert.Nil(t, sig)
		assert.Error(t, err)

		sig, err = client.SignAttributesGrpc(validPubM)
		assert.NotNil(t, sig)
		assert.Nil(t, err)

		assert.True(t, coconut.Verify(params, vk, validPubM, sig))
	}

	for _, invalidPubM := range invalidPubMs {
		sig, err := tcpclient.SignAttributesGrpc(invalidPubM)
		assert.Nil(t, sig)
		assert.Error(t, err)

		sig, err = client.SignAttributesGrpc(invalidPubM)
		assert.Nil(t, sig)
		assert.Error(t, err)
	}
}

// those tests could easily be combined with grpc version, however,
// I think it is worth to keep them sepearate in case implementation diverges significantly.
// The same applies to remaining TCP vs gRPC methods
func TestSignAttributes(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)
	cfgstr := createBasicClientCfgStr(issuerTCPAddresses, nil)
	cfgstr += logStr
	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)
	client, err := New(cfg)
	assert.Nil(t, err)

	grpccfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(nil, issuerGRPCAddresses) + logStr))
	grpcclient, err := New(grpccfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	// will be used for verification
	// tests for below method are separated.
	vk, err := client.GetAggregateVerificationKey()
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPubMs[2], nil),
	}

	for _, validPubM := range validPubMs {
		sig, err := grpcclient.SignAttributes(validPubM)
		assert.Nil(t, sig)
		assert.Error(t, err)

		sig, err = client.SignAttributes(validPubM)
		assert.NotNil(t, sig)
		assert.Nil(t, err)

		assert.True(t, coconut.Verify(params, vk, validPubM, sig))
	}

	for _, invalidPubM := range invalidPubMs {
		sig, err := grpcclient.SignAttributes(invalidPubM)
		assert.Nil(t, sig)
		assert.Error(t, err)

		sig, err = client.SignAttributes(invalidPubM)
		assert.Nil(t, sig)
		assert.Error(t, err)
	}
}

func TestHandleReceivedVerificationKeys(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)

	cfgStrTCP := createBasicClientCfgStr(issuerTCPAddresses, nil)
	cfgStrGRCP := createBasicClientCfgStr(nil, issuerGRPCAddresses)

	nonThrCfgStrTCP := cfgStrTCP + logStr
	nonThrCfgStrGRCP := cfgStrGRCP + logStr
	thrCfgStrTCP := cfgStrTCP + fmt.Sprintf("Threshold = %v\n", thresholdVal) + logStr
	thrCfgStrGRCP := cfgStrGRCP + fmt.Sprintf("Threshold = %v\n", thresholdVal) + logStr

	nonThresholdCfgTCP, err := cconfig.LoadBinary([]byte(nonThrCfgStrTCP))
	assert.Nil(t, err)
	nonThrClientTCP, err := New(nonThresholdCfgTCP)
	assert.Nil(t, err)

	nonThresholdCfgGRCP, err := cconfig.LoadBinary([]byte(nonThrCfgStrGRCP))
	assert.Nil(t, err)
	nonThrClientGRCP, err := New(nonThresholdCfgGRCP)
	assert.Nil(t, err)

	thresholdCfgTCP, err := cconfig.LoadBinary([]byte(thrCfgStrTCP))
	assert.Nil(t, err)
	thrClientTCP, err := New(thresholdCfgTCP)
	assert.Nil(t, err)

	thresholdCfgGRCP, err := cconfig.LoadBinary([]byte(thrCfgStrGRCP))
	assert.Nil(t, err)
	thrClientGRCP, err := New(thresholdCfgGRCP)
	assert.Nil(t, err)

	// since this method does not care if those are correct threshold credentials
	// (because there is no way to verify it without verification keys), we can obtain any set of signatures for testing
	validThrVks, validThrPP := getNVkPP(t, thresholdVal)
	fullValidVks, fullValidPP := getNVkPP(t, len(issuerTCPAddresses))

	for _, aggregate := range []bool{true, false} {
		for _, client := range []*Client{nonThrClientTCP, nonThrClientGRCP, thrClientTCP, thrClientGRCP} {
			var expectedLen int
			if aggregate {
				expectedLen = 1
			} else {
				expectedLen = len(fullValidVks)
			}

			vks, err := client.handleReceivedVerificationKeys(nil, nil, aggregate)
			assert.Nil(t, vks)
			assert.Error(t, err)

			vks, err = client.handleReceivedVerificationKeys(nil, fullValidPP, aggregate)
			assert.Nil(t, vks)
			assert.Error(t, err)

			vks, err = client.handleReceivedVerificationKeys(fullValidVks, nil, aggregate)
			if client.cfg.Client.Threshold == 0 {
				assert.NotNil(t, vks)
				assert.Len(t, vks, expectedLen)
				assert.Nil(t, err)
			} else {
				assert.Nil(t, vks)
				assert.Error(t, err)

				// inconsistent lengths check
				vks, err = client.handleReceivedVerificationKeys(fullValidVks[1:], fullValidPP, aggregate)
				assert.Nil(t, vks)
				assert.Error(t, err)
			}

			vks, err = client.handleReceivedVerificationKeys(fullValidVks, validThrPP, aggregate)
			assert.Nil(t, vks)
			assert.Error(t, err)

			vks, err = client.handleReceivedVerificationKeys(validThrVks, fullValidPP, aggregate)
			assert.Nil(t, vks)
			assert.Error(t, err)

			oldXs := fullValidPP.Xs()
			fullValidPP.Xs()[0] = fullValidPP.Xs()[2]
			vks, err = client.handleReceivedVerificationKeys(validThrVks, fullValidPP, aggregate)
			assert.Nil(t, vks)
			assert.Error(t, err)
			fullValidPP = coconut.NewPP(oldXs)

			invalidVks := []*coconut.VerificationKey{
				nil,
				&coconut.VerificationKey{},
				coconut.NewVk(validThrVks[0].G2(), nil, nil),
				coconut.NewVk(nil, validThrVks[0].Alpha(), nil),
				coconut.NewVk(nil, nil, validThrVks[0].Beta()),
				coconut.NewVk(validThrVks[0].G2(), validThrVks[0].Alpha(), []*Curve.ECP2{}),
			}

			oldVks := validThrVks
			for _, invVk := range invalidVks {
				validThrVks[0] = invVk
				// ensures the invalid entry gets removed and threshold check fails
				if client.cfg.Client.Threshold > 0 {
					vks, err = client.handleReceivedVerificationKeys(validThrVks, validThrPP, aggregate)
					assert.Nil(t, vks)
					assert.Error(t, err)

					vks, err = client.handleReceivedVerificationKeys(validThrVks, nil, aggregate)
					assert.Nil(t, vks)
					assert.Error(t, err)
				}
			}
			validThrVks = oldVks
		}
	}
}

func compareVks(vk1, vk2 *coconut.VerificationKey) bool {
	if !vk1.G2().Equals(vk2.G2()) || !vk1.Alpha().Equals(vk2.Alpha()) {
		return false
	}
	if len(vk1.Beta()) != len(vk2.Beta()) {
		return false
	}
	for i := range vk1.Beta() {
		if !vk1.Beta()[i].Equals(vk2.Beta()[i]) {
			return false
		}
	}
	return true
}

// not much to test here as most of the logic is handled by other methods
func TestGetVerificationKeysTCPAndGrpc(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)
	tcpcfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(issuerTCPAddresses, nil) + logStr))
	tcpclient, err := New(tcpcfg)
	assert.Nil(t, err)

	grpccfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(nil, issuerGRPCAddresses) + logStr))
	grpcClient, err := New(grpccfg)
	assert.Nil(t, err)

	for _, aggregate := range []bool{true, false} {
		vkatcp, err := grpcClient.GetAggregateVerificationKey()
		assert.Nil(t, vkatcp)
		assert.Error(t, err)

		vkatcp, err = tcpclient.GetAggregateVerificationKey()
		assert.True(t, vkatcp.Validate())
		assert.Nil(t, err)

		vkagrcp, err := tcpclient.GetAggregateVerificationKeyGrpc()
		assert.Nil(t, vkagrcp)
		assert.Error(t, err)

		vkagrcp, err = grpcClient.GetAggregateVerificationKeyGrpc()
		assert.True(t, vkagrcp.Validate())
		assert.Nil(t, err)

		vkstcp, err := tcpclient.GetVerificationKeys(aggregate)
		assert.NotNil(t, vkstcp)
		if aggregate {
			assert.Len(t, vkstcp, 1)
			assert.True(t, compareVks(vkstcp[0], vkatcp))
		} else {
			assert.Len(t, vkstcp, len(issuerTCPAddresses))
			params, err := coconut.Setup(5)
			assert.Nil(t, err)
			vka := coconut.AggregateVerificationKeys(params, vkstcp, nil)
			assert.True(t, compareVks(vka, vkatcp))
		}
		for _, vk := range vkstcp {
			assert.True(t, vk.Validate())
		}
		assert.Nil(t, err)

		vks, err := grpcClient.GetVerificationKeys(aggregate)
		assert.Nil(t, vks)
		assert.Error(t, err)

		vks, err = tcpclient.GetVerificationKeysGrpc(aggregate)
		assert.Nil(t, vks)
		assert.Error(t, err)

		vksgrcp, err := grpcClient.GetVerificationKeysGrpc(aggregate)
		assert.NotNil(t, vksgrcp)
		if aggregate {
			assert.Len(t, vksgrcp, 1)
			assert.True(t, compareVks(vksgrcp[0], vkagrcp))
		} else {
			assert.Len(t, vksgrcp, len(issuerGRPCAddresses))
			params, err := coconut.Setup(5)
			assert.Nil(t, err)
			vka := coconut.AggregateVerificationKeys(params, vksgrcp, nil)
			assert.True(t, compareVks(vka, vkagrcp))
		}
		for _, vk := range vksgrcp {
			assert.True(t, vk.Validate())
		}
		assert.Nil(t, err)

		// since issuers have the same set of keys, assert the returned keys are actually identical
		assert.True(t, compareVks(vkagrcp, vkatcp))
	}
}

func TestBlindSignAttributesGrpc(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)
	cfgstr := createBasicClientCfgStr(nil, issuerGRPCAddresses)
	cfgstr += logStr
	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)
	client, err := New(cfg)
	assert.Nil(t, err)

	tcpcfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(issuerTCPAddresses, nil) + logStr))
	tcpclient, err := New(tcpcfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	// will be used for verification
	// tests for below method are separated.
	vk, err := client.GetAggregateVerificationKeyGrpc()
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		[]*Curve.BIG{}, // here an empty slice is a valid option
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
	}

	validPrivMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
		getRandomAttributes(params.G, 3),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		append(validPubMs[2], nil),
	}

	invalidPrivMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPrivMs[2], nil),
	}

	for _, validPubM := range validPubMs {
		for _, validPrivM := range validPrivMs {
			sig, err := tcpclient.BlindSignAttributesGrpc(validPubM, validPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)

			sig, err = client.BlindSignAttributesGrpc(validPubM, validPrivM)
			assert.NotNil(t, sig)
			assert.Nil(t, err)

			blindShowMats, err := coconut.ShowBlindSignature(params, vk, sig, validPrivM)
			assert.Nil(t, err)

			assert.True(t, coconut.BlindVerify(params, vk, sig, blindShowMats, validPubM))
		}

		for _, invalidPrivM := range invalidPrivMs {
			sig, err := tcpclient.BlindSignAttributesGrpc(validPubM, invalidPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)

			sig, err = client.BlindSignAttributesGrpc(validPubM, invalidPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}
	}

	for _, invalidPubM := range invalidPubMs {
		for _, validPrivM := range validPrivMs {
			sig, err := tcpclient.BlindSignAttributesGrpc(invalidPubM, validPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)

			sig, err = client.BlindSignAttributesGrpc(invalidPubM, validPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}

		for _, invalidPrivM := range invalidPrivMs {
			sig, err := tcpclient.BlindSignAttributesGrpc(invalidPubM, invalidPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)

			sig, err = client.BlindSignAttributesGrpc(invalidPubM, invalidPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}
	}
}

func TestBlindSignAttributes(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)
	cfgstr := createBasicClientCfgStr(issuerTCPAddresses, nil)
	cfgstr += logStr
	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)
	client, err := New(cfg)
	assert.Nil(t, err)

	grpccfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(nil, issuerGRPCAddresses) + logStr))
	grpcclient, err := New(grpccfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	// will be used for verification
	// tests for below method are separated.
	vk, err := client.GetAggregateVerificationKey()
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		[]*Curve.BIG{}, // here an empty slice is a valid option
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
	}

	validPrivMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
		getRandomAttributes(params.G, 3),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		append(validPubMs[2], nil),
	}

	invalidPrivMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPrivMs[2], nil),
	}

	for _, validPubM := range validPubMs {
		for _, validPrivM := range validPrivMs {
			sig, err := grpcclient.BlindSignAttributes(validPubM, validPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)

			sig, err = client.BlindSignAttributes(validPubM, validPrivM)
			assert.NotNil(t, sig)
			assert.Nil(t, err)

			blindShowMats, err := coconut.ShowBlindSignature(params, vk, sig, validPrivM)
			assert.Nil(t, err)

			assert.True(t, coconut.BlindVerify(params, vk, sig, blindShowMats, validPubM))
		}

		for _, invalidPrivM := range invalidPrivMs {
			sig, err := grpcclient.BlindSignAttributes(validPubM, invalidPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)

			sig, err = client.BlindSignAttributes(validPubM, invalidPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}
	}

	for _, invalidPubM := range invalidPubMs {
		for _, validPrivM := range validPrivMs {
			sig, err := grpcclient.BlindSignAttributes(invalidPubM, validPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)

			sig, err = client.BlindSignAttributes(invalidPubM, validPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}

		for _, invalidPrivM := range invalidPrivMs {
			sig, err := grpcclient.BlindSignAttributes(invalidPubM, invalidPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)

			sig, err = client.BlindSignAttributes(invalidPubM, invalidPrivM)
			assert.Nil(t, sig)
			assert.Error(t, err)
		}
	}
}

func TestSendCredentialsForVerificationGrpc(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)
	cfgstr := createBasicClientCfgStr(nil, issuerGRPCAddresses)
	thrCfgStr := cfgstr + fmt.Sprintf("Threshold = %v\n", thresholdVal) + logStr
	cfgstr += logStr

	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)
	client, err := New(cfg)
	assert.Nil(t, err)

	thrcfg, err := cconfig.LoadBinary([]byte(thrCfgStr))
	assert.Nil(t, err)
	thrClient, err := New(thrcfg)
	assert.Nil(t, err)

	tcpcfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(issuerTCPAddresses, nil) + logStr))
	tcpclient, err := New(tcpcfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPubMs[2], nil),
	}

	for _, validPubM := range validPubMs {
		validThrSig, err := thrClient.SignAttributesGrpc(validPubM)
		assert.Nil(t, err)

		validSig, err := client.SignAttributesGrpc(validPubM)
		assert.Nil(t, err)

		isValid, err := tcpclient.SendCredentialsForVerificationGrpc(validPubM, validSig, nonThresholdProvider.grpcaddress)
		assert.False(t, isValid)
		assert.Error(t, err)

		nonExistentProvider := "127.0.0.1:54321"
		isValid, err = client.SendCredentialsForVerificationGrpc(validPubM, validSig, nonExistentProvider)
		assert.False(t, isValid)
		assert.Error(t, err)

		isValid, err = client.SendCredentialsForVerificationGrpc(validPubM, validSig, nonThresholdProvider.grpcaddress)
		assert.True(t, isValid)
		assert.Nil(t, err)

		isValid, err = thrClient.SendCredentialsForVerificationGrpc(validPubM, validThrSig, thresholdProvider.grpcaddress)
		assert.True(t, isValid)
		assert.Nil(t, err)

		// sanity checks
		isValid, err = client.SendCredentialsForVerificationGrpc(validPubM, validSig, thresholdProvider.grpcaddress)
		assert.False(t, isValid)
		assert.Nil(t, err)

		isValid, err = thrClient.SendCredentialsForVerificationGrpc(validPubM, validThrSig, nonThresholdProvider.grpcaddress)
		assert.False(t, isValid)
		assert.Nil(t, err)

		isValid, err = client.SendCredentialsForVerificationGrpc(validPubM, validThrSig, nonThresholdProvider.grpcaddress)
		assert.False(t, isValid)
		assert.Nil(t, err)

		isValid, err = thrClient.SendCredentialsForVerificationGrpc(validPubM, validSig, thresholdProvider.grpcaddress)
		assert.False(t, isValid)
		assert.Nil(t, err)

		// they won't produce valid credentials to begin with, but the point is to ensure
		// nothing is going to crash upon trying to parse the attributes during verification
		for _, invalidPubM := range invalidPubMs {
			isValid, err = client.SendCredentialsForVerificationGrpc(invalidPubM, validSig, nonThresholdProvider.grpcaddress)
			assert.False(t, isValid)
			assert.Error(t, err)

			isValid, err = thrClient.SendCredentialsForVerificationGrpc(invalidPubM, validThrSig, thresholdProvider.grpcaddress)
			assert.False(t, isValid)
			assert.Error(t, err)
		}

		invalidSigs := []*coconut.Signature{
			nil,
			&coconut.Signature{},
			coconut.NewSignature(validThrSig.Sig1(), nil),
			coconut.NewSignature(nil, validThrSig.Sig2()),
		}

		for _, invalidSig := range invalidSigs {
			isValid, err := thrClient.SendCredentialsForVerificationGrpc(validPubM, invalidSig, nonThresholdProvider.grpcaddress)
			assert.False(t, isValid)
			assert.Error(t, err)
		}
	}
}

func TestSendCredentialsForVerification(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "DEBUG"`)
	cfgstr := createBasicClientCfgStr(issuerTCPAddresses, nil)
	thrCfgStr := cfgstr + fmt.Sprintf("Threshold = %v\n", thresholdVal) + logStr
	cfgstr += logStr

	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)
	client, err := New(cfg)
	assert.Nil(t, err)

	thrcfg, err := cconfig.LoadBinary([]byte(thrCfgStr))
	assert.Nil(t, err)
	thrClient, err := New(thrcfg)
	assert.Nil(t, err)

	grpccfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(nil, issuerGRPCAddresses) + logStr))
	grpcClient, err := New(grpccfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 3),
		getRandomAttributes(params.G, 5),
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPubMs[2], nil),
	}

	for _, validPubM := range validPubMs {
		validThrSig, err := thrClient.SignAttributes(validPubM)
		assert.Nil(t, err)

		validSig, err := client.SignAttributes(validPubM)
		assert.Nil(t, err)

		isValid, err := grpcClient.SendCredentialsForVerification(validPubM, validSig, providerTCPAddresses[1])
		assert.False(t, isValid)
		assert.Error(t, err)

		nonExistentProvider := "127.0.0.1:54321"
		isValid, err = client.SendCredentialsForVerification(validPubM, validSig, nonExistentProvider)
		assert.False(t, isValid)
		assert.Error(t, err)

		isValid, err = client.SendCredentialsForVerification(validPubM, validSig, providerTCPAddresses[1])
		assert.True(t, isValid)
		assert.Nil(t, err)

		isValid, err = thrClient.SendCredentialsForVerification(validPubM, validThrSig, providerTCPAddresses[0])
		assert.True(t, isValid)
		assert.Nil(t, err)

		// sanity checks
		isValid, err = client.SendCredentialsForVerification(validPubM, validSig, providerTCPAddresses[0])
		assert.False(t, isValid)
		assert.Nil(t, err)

		isValid, err = thrClient.SendCredentialsForVerification(validPubM, validThrSig, providerTCPAddresses[1])
		assert.False(t, isValid)
		assert.Nil(t, err)

		isValid, err = client.SendCredentialsForVerification(validPubM, validThrSig, providerTCPAddresses[1])
		assert.False(t, isValid)
		assert.Nil(t, err)

		isValid, err = thrClient.SendCredentialsForVerification(validPubM, validSig, providerTCPAddresses[0])
		assert.False(t, isValid)
		assert.Nil(t, err)

		// they won't produce valid credentials to begin with, but the point is to ensure
		// nothing is going to crash upon trying to parse the attributes during verification
		for _, invalidPubM := range invalidPubMs {
			isValid, err = client.SendCredentialsForVerification(invalidPubM, validSig, providerTCPAddresses[1])
			assert.False(t, isValid)
			assert.Error(t, err)

			isValid, err = thrClient.SendCredentialsForVerification(invalidPubM, validThrSig, providerTCPAddresses[0])
			assert.False(t, isValid)
			assert.Error(t, err)
		}

		invalidSigs := []*coconut.Signature{
			nil,
			&coconut.Signature{},
			coconut.NewSignature(validThrSig.Sig1(), nil),
			coconut.NewSignature(nil, validThrSig.Sig2()),
		}

		for _, invalidSig := range invalidSigs {
			isValid, err := thrClient.SendCredentialsForVerification(validPubM, invalidSig, providerTCPAddresses[1])
			assert.False(t, isValid)
			assert.Error(t, err)
		}
	}
}

func TestPrepareBlindVerifyRequest(t *testing.T) {
	// it does not matter if client is threshold/not
	// grpc/tcp makes no difference at all, only whether vk will be obtained
	// by grpc or tcp call
	cfgstr := createBasicClientCfgStr(issuerTCPAddresses, nil)
	cfgstr += string(`PersistentKeys = false

[Logging]
Disable = true
Level = "DEBUG"
		`)

	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)

	client, err := New(cfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		[]*Curve.BIG{},
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
	}

	validPrivMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
		getRandomAttributes(params.G, 3),
	}

	avk, err := client.GetAggregateVerificationKey()
	assert.Nil(t, err)

	for _, validPubM := range validPubMs {
		for _, validPrivM := range validPrivMs {
			validSig, err := client.BlindSignAttributes(validPubM, validPrivM)
			assert.Nil(t, err)

			blindverifyRequest, err := client.prepareBlindVerifyRequest(validPubM, validPrivM, validSig, nil)
			assert.NotNil(t, blindverifyRequest)
			assert.Nil(t, err)

			blindverifyRequest, err = client.prepareBlindVerifyRequest(validPubM, validPrivM, validSig, avk)
			assert.NotNil(t, blindverifyRequest)
			assert.Nil(t, err)
		}
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		append(validPubMs[2], nil),
	}

	invalidPrivMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPrivMs[2], nil),
	}

	// need to create a valid signature in order to be able to call the method
	// that is being tested
	validTestSig, err := client.BlindSignAttributes(validPubMs[2], validPrivMs[2])
	assert.Nil(t, err)
	invalidSigs := []*coconut.Signature{
		nil,
		&coconut.Signature{},
		coconut.NewSignature(validTestSig.Sig1(), nil),
		coconut.NewSignature(nil, validTestSig.Sig2()),
	}

	invalidVks := []*coconut.VerificationKey{
		&coconut.VerificationKey{},
		coconut.NewVk(avk.G2(), nil, nil),
		coconut.NewVk(nil, avk.Alpha(), nil),
		coconut.NewVk(nil, nil, avk.Beta()),
		coconut.NewVk(avk.G2(), avk.Alpha(), []*Curve.ECP2{}),
	}

	// // similarly to before, all those only ensure that nothing crashes while parsing bad attributes
	for _, invalidPubM := range invalidPubMs {
		blindverifyRequest, err := client.prepareBlindVerifyRequest(invalidPubM, validPrivMs[2], validTestSig, avk)
		assert.Nil(t, blindverifyRequest)
		assert.Error(t, err)
	}

	for _, invalidPrivM := range invalidPrivMs {
		blindverifyRequest, err := client.prepareBlindVerifyRequest(validPubMs[2], invalidPrivM, validTestSig, avk)
		assert.Nil(t, blindverifyRequest)
		assert.Error(t, err)
	}

	for _, invalidSig := range invalidSigs {
		blindverifyRequest, err := client.prepareBlindVerifyRequest(validPubMs[2], validPrivMs[2], invalidSig, avk)
		assert.Nil(t, blindverifyRequest)
		assert.Error(t, err)
	}

	for _, invalidVk := range invalidVks {
		blindverifyRequest, err := client.prepareBlindVerifyRequest(validPubMs[2], validPrivMs[2], validTestSig, invalidVk)
		assert.Nil(t, blindverifyRequest)
		assert.Error(t, err)
	}
}

func TestSendCredentialsForBlindVerificationGrpc(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "ERROR"`)
	cfgstr := createBasicClientCfgStr(nil, issuerGRPCAddresses)
	thrCfgStr := cfgstr + fmt.Sprintf("Threshold = %v\n", thresholdVal) + logStr
	cfgstr += logStr

	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)
	client, err := New(cfg)
	assert.Nil(t, err)

	thrcfg, err := cconfig.LoadBinary([]byte(thrCfgStr))
	assert.Nil(t, err)
	thrClient, err := New(thrcfg)
	assert.Nil(t, err)

	tcpcfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(issuerTCPAddresses, nil) + logStr))
	tcpclient, err := New(tcpcfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		[]*Curve.BIG{},
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
	}

	validPrivMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
		getRandomAttributes(params.G, 3),
	}

	avk, err := client.GetAggregateVerificationKeyGrpc()
	assert.Nil(t, err)

	thravk, err := thrClient.GetAggregateVerificationKeyGrpc()
	assert.Nil(t, err)

	for _, validPubM := range validPubMs {
		for _, validPrivM := range validPrivMs {
			validThrSig, err := thrClient.BlindSignAttributesGrpc(validPubM, validPrivM)
			assert.Nil(t, err)

			validSig, err := client.BlindSignAttributesGrpc(validPubM, validPrivM)
			assert.Nil(t, err)

			isValid, err := tcpclient.SendCredentialsForBlindVerificationGrpc(validPubM, validPrivM, validSig, thresholdProvider.grpcaddress, avk)
			assert.False(t, isValid)
			assert.Error(t, err)

			nonExistentProvider := "127.0.0.1:54321"
			isValid, err = client.SendCredentialsForBlindVerificationGrpc(validPubM, validPrivM, validSig, nonExistentProvider, avk)
			assert.False(t, isValid)
			assert.Error(t, err)

			isValid, err = client.SendCredentialsForBlindVerificationGrpc(validPubM, validPrivM, validSig, nonThresholdProvider.grpcaddress, avk)
			assert.True(t, isValid)
			assert.Nil(t, err)

			isValid, err = thrClient.SendCredentialsForBlindVerificationGrpc(validPubM, validPrivM, validThrSig, thresholdProvider.grpcaddress, thravk)
			assert.True(t, isValid)
			assert.Nil(t, err)

			// sanity checks
			isValid, err = client.SendCredentialsForBlindVerificationGrpc(validPubM, validPrivM, validSig, thresholdProvider.grpcaddress, avk)
			assert.False(t, isValid)
			assert.Nil(t, err)

			isValid, err = thrClient.SendCredentialsForBlindVerificationGrpc(validPubM, validPrivM, validThrSig, nonThresholdProvider.grpcaddress, thravk)
			assert.False(t, isValid)
			assert.Nil(t, err)

			isValid, err = client.SendCredentialsForBlindVerificationGrpc(validPubM, validPrivM, validThrSig, nonThresholdProvider.grpcaddress, avk)
			assert.False(t, isValid)
			assert.Nil(t, err)

			isValid, err = thrClient.SendCredentialsForBlindVerificationGrpc(validPubM, validPrivM, validSig, thresholdProvider.grpcaddress, thravk)
			assert.False(t, isValid)
			assert.Nil(t, err)
		}
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		append(validPubMs[2], nil),
	}

	invalidPrivMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPrivMs[2], nil),
	}

	// need to create a valid signature in order to be able to call the method
	// that is being tested
	validTestSig, err := client.BlindSignAttributesGrpc(validPubMs[2], validPrivMs[2])
	assert.Nil(t, err)
	invalidSigs := []*coconut.Signature{
		nil,
		&coconut.Signature{},
		coconut.NewSignature(validTestSig.Sig1(), nil),
		coconut.NewSignature(nil, validTestSig.Sig2()),
	}

	invalidVks := []*coconut.VerificationKey{
		&coconut.VerificationKey{},
		coconut.NewVk(avk.G2(), nil, nil),
		coconut.NewVk(nil, avk.Alpha(), nil),
		coconut.NewVk(nil, nil, avk.Beta()),
		coconut.NewVk(avk.G2(), avk.Alpha(), []*Curve.ECP2{}),
	}

	// // similarly to before, all those only ensure that nothing crashes while parsing bad attributes
	for _, invalidPubM := range invalidPubMs {
		isValid, err := client.SendCredentialsForBlindVerificationGrpc(invalidPubM, validPrivMs[2], validTestSig, nonThresholdProvider.grpcaddress, avk)
		assert.False(t, isValid)
		assert.Error(t, err)
	}

	for _, invalidPrivM := range invalidPrivMs {
		isValid, err := client.SendCredentialsForBlindVerificationGrpc(validPubMs[2], invalidPrivM, validTestSig, nonThresholdProvider.grpcaddress, avk)
		assert.False(t, isValid)
		assert.Error(t, err)
	}

	for _, invalidSig := range invalidSigs {
		isValid, err := client.SendCredentialsForBlindVerificationGrpc(validPubMs[2], validPrivMs[2], invalidSig, nonThresholdProvider.grpcaddress, avk)
		assert.False(t, isValid)
		assert.Error(t, err)
	}

	for _, invalidVk := range invalidVks {
		isValid, err := client.SendCredentialsForBlindVerificationGrpc(validPubMs[2], validPrivMs[2], validTestSig, nonThresholdProvider.grpcaddress, invalidVk)
		assert.False(t, isValid)
		assert.Error(t, err)
	}
}

func TestSendCredentialsForBlindVerification(t *testing.T) {
	logStr := string(`PersistentKeys = false
	[Logging]
	Disable = true
	Level = "ERROR"`)
	cfgstr := createBasicClientCfgStr(issuerTCPAddresses, nil)
	thrCfgStr := cfgstr + fmt.Sprintf("Threshold = %v\n", thresholdVal) + logStr
	cfgstr += logStr

	cfg, err := cconfig.LoadBinary([]byte(cfgstr))
	assert.Nil(t, err)
	client, err := New(cfg)
	assert.Nil(t, err)

	thrcfg, err := cconfig.LoadBinary([]byte(thrCfgStr))
	assert.Nil(t, err)
	thrClient, err := New(thrcfg)
	assert.Nil(t, err)

	grpccfg, err := cconfig.LoadBinary([]byte(createBasicClientCfgStr(nil, issuerGRPCAddresses) + logStr))
	grpcClient, err := New(grpccfg)
	assert.Nil(t, err)

	params, err := coconut.Setup(5)
	assert.Nil(t, err)

	validPubMs := [][]*Curve.BIG{
		[]*Curve.BIG{},
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
	}

	validPrivMs := [][]*Curve.BIG{
		getRandomAttributes(params.G, 1),
		getRandomAttributes(params.G, 2),
		getRandomAttributes(params.G, 3),
	}

	avk, err := client.GetAggregateVerificationKey()
	assert.Nil(t, err)

	thravk, err := thrClient.GetAggregateVerificationKey()
	assert.Nil(t, err)

	for _, validPubM := range validPubMs {
		for _, validPrivM := range validPrivMs {
			validThrSig, err := thrClient.BlindSignAttributes(validPubM, validPrivM)
			assert.Nil(t, err)

			validSig, err := client.BlindSignAttributes(validPubM, validPrivM)
			assert.Nil(t, err)

			isValid, err := grpcClient.SendCredentialsForBlindVerification(validPubM, validPrivM, validSig, thresholdProvider.tcpaddress, avk)
			assert.False(t, isValid)
			assert.Error(t, err)

			nonExistentProvider := "127.0.0.1:54321"
			isValid, err = client.SendCredentialsForBlindVerification(validPubM, validPrivM, validSig, nonExistentProvider, avk)
			assert.False(t, isValid)
			assert.Error(t, err)

			isValid, err = client.SendCredentialsForBlindVerification(validPubM, validPrivM, validSig, nonThresholdProvider.tcpaddress, avk)
			assert.True(t, isValid)
			assert.Nil(t, err)

			isValid, err = thrClient.SendCredentialsForBlindVerification(validPubM, validPrivM, validThrSig, thresholdProvider.tcpaddress, thravk)
			assert.True(t, isValid)
			assert.Nil(t, err)

			// sanity checks
			isValid, err = client.SendCredentialsForBlindVerification(validPubM, validPrivM, validSig, thresholdProvider.tcpaddress, avk)
			assert.False(t, isValid)
			assert.Nil(t, err)

			isValid, err = thrClient.SendCredentialsForBlindVerification(validPubM, validPrivM, validThrSig, nonThresholdProvider.tcpaddress, thravk)
			assert.False(t, isValid)
			assert.Nil(t, err)

			isValid, err = client.SendCredentialsForBlindVerification(validPubM, validPrivM, validThrSig, nonThresholdProvider.tcpaddress, avk)
			assert.False(t, isValid)
			assert.Nil(t, err)

			isValid, err = thrClient.SendCredentialsForBlindVerification(validPubM, validPrivM, validSig, thresholdProvider.tcpaddress, thravk)
			assert.False(t, isValid)
			assert.Nil(t, err)
		}
	}

	invalidPubMs := [][]*Curve.BIG{
		nil,
		append(validPubMs[2], nil),
	}

	invalidPrivMs := [][]*Curve.BIG{
		nil,
		[]*Curve.BIG{},
		append(validPrivMs[2], nil),
	}

	// need to create a valid signature in order to be able to call the method
	// that is being tested
	validTestSig, err := client.BlindSignAttributes(validPubMs[2], validPrivMs[2])
	assert.Nil(t, err)
	invalidSigs := []*coconut.Signature{
		nil,
		&coconut.Signature{},
		coconut.NewSignature(validTestSig.Sig1(), nil),
		coconut.NewSignature(nil, validTestSig.Sig2()),
	}

	invalidVks := []*coconut.VerificationKey{
		&coconut.VerificationKey{},
		coconut.NewVk(avk.G2(), nil, nil),
		coconut.NewVk(nil, avk.Alpha(), nil),
		coconut.NewVk(nil, nil, avk.Beta()),
		coconut.NewVk(avk.G2(), avk.Alpha(), []*Curve.ECP2{}),
	}

	// // similarly to before, all those only ensure that nothing crashes while parsing bad attributes
	for _, invalidPubM := range invalidPubMs {
		isValid, err := client.SendCredentialsForBlindVerification(invalidPubM, validPrivMs[2], validTestSig, nonThresholdProvider.tcpaddress, avk)
		assert.False(t, isValid)
		assert.Error(t, err)
	}

	for _, invalidPrivM := range invalidPrivMs {
		isValid, err := client.SendCredentialsForBlindVerification(validPubMs[2], invalidPrivM, validTestSig, nonThresholdProvider.tcpaddress, avk)
		assert.False(t, isValid)
		assert.Error(t, err)
	}

	for _, invalidSig := range invalidSigs {
		isValid, err := client.SendCredentialsForBlindVerification(validPubMs[2], validPrivMs[2], invalidSig, nonThresholdProvider.tcpaddress, avk)
		assert.False(t, isValid)
		assert.Error(t, err)
	}

	for _, invalidVk := range invalidVks {
		isValid, err := client.SendCredentialsForBlindVerification(validPubMs[2], validPrivMs[2], validTestSig, nonThresholdProvider.tcpaddress, invalidVk)
		assert.False(t, isValid)
		assert.Error(t, err)
	}
}
