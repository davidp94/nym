// utils.go - set of utility functions used by client and server.
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

// Package utils consists of set of helper functions used by both client and server.
// Note that in the next minor release, the package will be renamed and
// the file will be moved to different directory.
package comm

import (
	"encoding/binary"
	"io"
	"net"
	"sort"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/common/comm/packet"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"gopkg.in/op/go-logging.v1"
)

// ServerMetadata encapsulates all server-related information passed in each
// request and response.
type ServerMetadata struct {
	Address string
	ID      int
}

// ServerResponse represents raw data returned from a particular server
// as well as the associated metadata when the request was sent on a TCP socket.
type ServerResponse struct {
	MarshaledData  []byte
	ServerMetadata *ServerMetadata
}

// ServerRequest represents raw data sent to a particular server
// as well as the associated metadata when the request is sent on a TCP socket.
type ServerRequest struct {
	MarshaledData  []byte // it's just a marshaled packet, but is kept generic in case the implementation changes
	ServerMetadata *ServerMetadata
}

// ServerResponseGrpc represents raw data returned from a particular server
// as well as the associated metadata when the request was sent as a gRPC request.
type ServerResponseGrpc struct {
	Message        proto.Message
	ServerMetadata *ServerMetadata
}

// ServerRequestGrpc represents raw data sent to a particular server
// as well as the associated metadata when the request is sent as a gRPC request.
type ServerRequestGrpc struct {
	Message        proto.Message
	ServerMetadata *ServerMetadata
}

// ReadPacketFromConn reads all data from a given connection and
// unmarshals it into a packet instance.
func ReadPacketFromConn(conn net.Conn) (*packet.Packet, error) {
	var err error
	tmp := make([]byte, 4) // packetlength
	if _, err = io.ReadFull(conn, tmp); err != nil {
		return nil, err
	}
	packetOutLength := binary.BigEndian.Uint32(tmp)
	packetOutBytes := make([]byte, packetOutLength)
	copy(packetOutBytes, tmp)
	if _, err = io.ReadFull(conn, packetOutBytes[4:]); err != nil {
		return nil, err
	}
	return packet.FromBytes(packetOutBytes)
}

// SendServerRequests starts set of goroutines sending requests on TCP sockets to particular servers.
// Number of goroutines is limited by maxReqs argument.
// It returns the channel to write the requests to.
// errcheck is ignored to make it not complain about not checking for err in conn.Close()
// nolint: errcheck
func SendServerRequests(rCh chan<- *ServerResponse, maxReqs int, log *logging.Logger, connT int) chan<- *ServerRequest {
	ch := make(chan *ServerRequest)
	for i := 0; i < maxReqs; i++ {
		go func() {
			for {
				req, ok := <-ch
				if !ok {
					return
				}

				log.Debugf("Dialing %v", req.ServerMetadata.Address)
				conn, err := net.Dial("tcp", req.ServerMetadata.Address)
				if err != nil {
					log.Errorf("Could not dial %v", req.ServerMetadata.Address)
					continue
				}
				defer conn.Close()

				// currently will never be thrown since there is no writedeadline
				if _, werr := conn.Write(req.MarshaledData); werr != nil {
					log.Errorf("Failed to write to connection: %v", werr)
					continue
				}

				sderr := conn.SetReadDeadline(time.Now().Add(time.Duration(connT) * time.Millisecond))
				if sderr != nil {
					log.Errorf("Failed to set read deadline for connection: %v", sderr)
					continue
				}

				resp, err := ReadPacketFromConn(conn)
				if err != nil {
					log.Errorf("Received invalid response from %v: %v", req.ServerMetadata.Address, err)
				} else {
					rCh <- &ServerResponse{
						MarshaledData: resp.Payload(),
						ServerMetadata: &ServerMetadata{
							Address: req.ServerMetadata.Address,
							ID:      req.ServerMetadata.ID,
						},
					}
				}
			}
		}()
	}
	return ch
}

// WaitForServerResponses is responsible for keeping track of request statuses and possible timeouts
// if some requests fail to resolve in given time period.
func WaitForServerResponses(rCh <-chan *ServerResponse, responses []*ServerResponse, log *logging.Logger, reqT int) {
	timeout := time.After(time.Duration(reqT) * time.Millisecond)
	i := 0
	for {
		select {
		case resp := <-rCh:
			log.Debug("Received a reply from IA (%v)", resp.ServerMetadata.Address)
			responses[i] = resp
			i++

			if i == len(responses) {
				log.Debug("Got responses from all servers")
				return
			}
		case <-timeout:
			log.Notice("Timed out while sending requests")
			return
		}
	}
}

// ParseVerificationKeyResponses takes a slice containing ServerResponses with marshalled verification keys and
// processes it accordingly to threshold system parameter.
// nolint: lll
func ParseVerificationKeyResponses(responses []*ServerResponse, isThreshold bool, log *logging.Logger) ([]*coconut.VerificationKey, *coconut.PolynomialPoints) {
	vks := make([]*coconut.VerificationKey, 0, len(responses))
	xs := make([]*Curve.BIG, 0, len(responses))

	for i := range responses {
		if responses[i] != nil {
			resp := &commands.VerificationKeyResponse{}
			if err := proto.Unmarshal(responses[i].MarshaledData, resp); err != nil {
				log.Errorf("Failed to unmarshal response from: %v", responses[i].ServerMetadata.Address)
				continue
			}
			if resp.Status.Code != int32(commands.StatusCode_OK) {
				log.Errorf("Received invalid response with status: %v. Error: %v", resp.Status.Code, resp.Status.Message)
				continue
			}
			vk := &coconut.VerificationKey{}
			if err := vk.FromProto(resp.Vk); err != nil {
				log.Errorf("Failed to unmarshal received verification key from %v", responses[i].ServerMetadata.Address)
				continue // can still succeed with >= threshold vk
			}
			vks = append(vks, vk)
			if isThreshold {
				// no point in computing that if we won't need it
				xs = append(xs, Curve.NewBIGint(responses[i].ServerMetadata.ID))
			}
		}
	}

	if isThreshold {
		return vks, coconut.NewPP(xs)
	}

	if len(vks) != len(responses) {
		log.Errorf("This is not threshold system and some of the received responses were invalid")
		return nil, nil
	}

	// works under assumption that servers specified in config file are ordered by their IDs
	// which will in most cases be the case since they're just going to be 1,2,.., etc.
	// a more general solution would require modifying the function signature
	// and this use case is too niche to warrant the change.
	sort.Slice(responses, func(i, j int) bool { return responses[i].ServerMetadata.ID < responses[j].ServerMetadata.ID })

	return vks, nil
}

func makeProtoStatus(code commands.StatusCode, message string) *commands.Status {
	return &commands.Status{
		Code:    int32(code),
		Message: message,
	}
}

// ResolveServerRequest awaits for a response from a cryptoworker and acts on it appropriately adding relevant metadata.
// nolint: lll, gocyclo
func ResolveServerRequest(cmd commands.Command, resCh chan *commands.Response, log *logging.Logger, requestTimeout int, provReady bool) proto.Message {
	timeout := time.After(time.Duration(requestTimeout) * time.Millisecond)

	var data interface{}
	var protoStatus *commands.Status

	select {
	case resp := <-resCh:
		log.Debug("Received response from the worker")
		if resp.Data != nil && len(resp.ErrorMessage) == 0 && resp.ErrorStatus == commands.StatusCode_UNKNOWN {
			resp.ErrorStatus = commands.StatusCode_OK
		}

		data = resp.Data
		protoStatus = makeProtoStatus(resp.ErrorStatus, resp.ErrorMessage)

	// we can wait up to requestTiemout to resolve request
	// todo: a way to cancel the request because even though it timeouts, the worker is still working on it
	case <-timeout:
		protoStatus = makeProtoStatus(commands.StatusCode_REQUEST_TIMEOUT, "Request took too long to resolve.")
		log.Error("Failed to resolve request - timeout")
	}

	var protoResp proto.Message
	var err error
	switch cmd.(type) {
	case *commands.SignRequest:
		protoSig := &coconut.ProtoSignature{}
		if data != nil {
			protoSig, err = data.(*coconut.Signature).ToProto()
			if err != nil {
				protoStatus = makeProtoStatus(commands.StatusCode_PROCESSING_ERROR, "Failed to marshal response.")
				log.Errorf("Error while creating response: %v", err)
			}
		}
		protoResp = &commands.SignResponse{
			Sig:    protoSig,
			Status: protoStatus,
		}
	case *commands.VerificationKeyRequest:
		protoVk := &coconut.ProtoVerificationKey{}
		if data != nil {
			protoVk, err = data.(*coconut.VerificationKey).ToProto()
			if err != nil {
				protoStatus = makeProtoStatus(commands.StatusCode_PROCESSING_ERROR, "Failed to marshal response.")
				log.Errorf("Error while creating response: %v", err)
			}
		}
		protoResp = &commands.VerificationKeyResponse{
			Vk:     protoVk,
			Status: protoStatus,
		}
	case *commands.VerifyRequest:
		if data != nil && provReady {
			isValid := data.(bool)
			protoResp = &commands.VerifyResponse{
				IsValid: isValid,
				Status:  protoStatus,
			}
			log.Debugf("Was the received credential valid: %v", isValid)
		} else {
			protoResp = &commands.VerifyResponse{
				Status: makeProtoStatus(commands.StatusCode_UNAVAILABLE, "The provider has not finished startup yet"),
			}
			log.Notice("Verification request to the server, while it has not finished startup (or data was nil)")
			// log.Critical("HAPPENED DURING CLIENT TESTS - nil data, NEED TO FIX WHEN CREATING SERVER TESTS!! (data is nil)")
		}
	case *commands.BlindSignRequest:
		protoBlindSig := &coconut.ProtoBlindedSignature{}
		if data != nil {
			protoBlindSig, err = data.(*coconut.BlindedSignature).ToProto()
			if err != nil {
				protoStatus = makeProtoStatus(commands.StatusCode_PROCESSING_ERROR, "Failed to marshal response.")
				log.Errorf("Error while creating response: %v", err)
			}
		}
		protoResp = &commands.BlindSignResponse{
			Sig:    protoBlindSig,
			Status: protoStatus,
		}
	case *commands.BlindVerifyRequest:
		if data != nil && provReady {
			isValid := data.(bool)
			protoResp = &commands.BlindVerifyResponse{
				IsValid: isValid,
				Status:  protoStatus,
			}
			log.Debugf("Was the received credential valid: %v", isValid)
		} else {
			protoResp = &commands.BlindVerifyResponse{
				Status: makeProtoStatus(commands.StatusCode_UNAVAILABLE, "The provider has not finished startup yet"),
			}
			log.Notice("Blind Verification request to the server, while it has not finished startup (or data was nil)")
			// log.Critical("HAPPENED DURING CLIENT TESTS - nil data, NEED TO FIX WHEN CREATING SERVER TESTS!! (data is nil)")
		}
	default:
		log.Errorf("Received an unrecognized command.")
		return nil
	}
	return protoResp
}

// RequestParams encapsulates all information required by GetServerResponses
// including server addresses and all timeout values.
type RequestParams struct {
	MarshaledPacket   []byte
	MaxRequests       int
	ConnectionTimeout int
	RequestTimeout    int
	ServerAddresses   []string
	ServerIDs         []int
}

// GetServerResponses writes requests to all server specified in the params according to the set params.
// todo: once server.go is refactored, if the function is not used there, move it to client.go
// func GetServerResponses(packet []byte, maxR int, connT int, reqT int, addrs []string, ids []int) []*ServerResponse {
func GetServerResponses(requestParams *RequestParams, log *logging.Logger) []*ServerResponse {

	responses := make([]*ServerResponse, len(requestParams.ServerAddresses)) // can't possibly get more results
	respCh := make(chan *ServerResponse)
	reqCh := SendServerRequests(respCh, requestParams.MaxRequests, log, requestParams.ConnectionTimeout)

	// write requests in a goroutine so we wouldn't block when trying to read responses
	go func() {
		for i := range requestParams.ServerAddresses {
			log.Debug("Writing request to %v", requestParams.ServerAddresses[i])
			reqCh <- &ServerRequest{
				MarshaledData: requestParams.MarshaledPacket,
				ServerMetadata: &ServerMetadata{
					Address: requestParams.ServerAddresses[i],
					ID:      requestParams.ServerIDs[i],
				},
			}
		}
	}()

	WaitForServerResponses(respCh, responses, log, requestParams.RequestTimeout)
	close(reqCh)
	return responses
}
