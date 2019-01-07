// set of helper functions used by both client and sever

package utils

import (
	"encoding/binary"
	"io"
	"net"
	"sort"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/server/commands"
	"0xacab.org/jstuczyn/CoconutGo/server/packet"
	"github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"gopkg.in/op/go-logging.v1"
)

// all we receive are either vk/sigs/blindsigs and all of them require ID (if treshold is used)
type ServerResponse struct {
	MarshaledData []byte
	ServerAddress string // not really needed, but might be useful for auditing
	ServerID      int    // will be needed for threshold aggregation
}

type ServerRequest struct {
	MarshaledData []byte // it's just a marshaled packet, but keep it generic in case the implementation changes
	ServerAddress string
	ServerID      int
}

type ServerResponseGrpc struct {
	Message       proto.Message
	ServerAddress string // not really needed, but might be useful for auditing
	ServerID      int    // will be needed for threshold aggregation
}

type ServerRequestGrpc struct {
	Message       proto.Message
	ServerAddress string
	ServerID      int
}

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

func CommandToMarshaledPacket(cmd commands.Command, cmdID commands.CommandID) []byte {
	payloadBytes, err := proto.Marshal(cmd)
	if err != nil {
		return nil
	}
	rawCmd := commands.NewRawCommand(cmdID, payloadBytes)
	cmdBytes := rawCmd.ToBytes()

	packetIn := packet.NewPacket(cmdBytes)
	packetBytes, err := packetIn.MarshalBinary()
	if err != nil {
		return nil
	}
	return packetBytes
}

func SendServerRequests(respCh chan<- *ServerResponse, maxRequests int, log *logging.Logger, connectTimeout int) chan<- *ServerRequest {
	ch := make(chan *ServerRequest)
	for i := 0; i < maxRequests; i++ {
		go func() {
			for {
				req, ok := <-ch
				if !ok {
					return
				}

				log.Debugf("Dialing %v", req.ServerAddress)
				conn, err := net.Dial("tcp", req.ServerAddress)
				if err != nil {
					log.Errorf("Could not dial %v", req.ServerAddress)
					continue
				}
				// defer

				conn.Write(req.MarshaledData)
				conn.SetReadDeadline(time.Now().Add(time.Duration(connectTimeout) * time.Millisecond))

				resp, err := ReadPacketFromConn(conn)
				conn.Close()
				if err != nil {
					log.Errorf("Received invalid response from %v: %v", req.ServerAddress, err)
				} else {
					respCh <- &ServerResponse{MarshaledData: resp.Payload(), ServerID: req.ServerID, ServerAddress: req.ServerAddress}
				}
			}
		}()
	}
	return ch
}

// used by both clients and providers
func WaitForServerResponses(respCh <-chan *ServerResponse, responses []*ServerResponse, log *logging.Logger, requestTimeout int) {
	timeout := time.After(time.Duration(requestTimeout) * time.Millisecond)
	i := 0
	for {
		select {
		case resp := <-respCh:
			log.Debug("Received a reply from IA (%v)", resp.ServerAddress)
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

func ParseVerificationKeyResponses(responses []*ServerResponse, isThreshold bool, log *logging.Logger) ([]*coconut.VerificationKey, *coconut.PolynomialPoints) {
	vks := make([]*coconut.VerificationKey, 0, len(responses))
	xs := make([]*Curve.BIG, 0, len(responses))

	sort.Slice(responses, func(i, j int) bool { return responses[i].ServerID < responses[j].ServerID })

	for i := range responses {
		if responses[i] != nil {
			resp := &commands.VerificationKeyResponse{}
			if err := proto.Unmarshal(responses[i].MarshaledData, resp); err != nil {
				log.Errorf("Failed to unmarshal response from: %v", responses[i].ServerAddress)
				continue
			}
			if resp.Status.Code != int32(commands.StatusCode_OK) {
				log.Errorf("Received invalid response with status: %v. Error: %v", resp.Status.Code, resp.Status.Message)
				continue
			}
			vk := &coconut.VerificationKey{}
			if err := vk.FromProto(resp.Vk); err != nil {
				log.Errorf("Failed to unmarshal received verification key from %v", responses[i].ServerAddress)
				continue // can still succeed with >= threshold vk
			}
			vks = append(vks, vk)
			if isThreshold {
				xs = append(xs, Curve.NewBIGint(responses[i].ServerID)) // no point in computing that if we won't need it
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

	return vks, nil
}

func ResolveServerRequest(cmd commands.Command, resCh chan *commands.Response, log *logging.Logger, requestTimeout int, provReady bool) proto.Message {
	timeout := time.After(time.Duration(requestTimeout) * time.Millisecond)

	var data interface{}
	protoStatus := &commands.Status{}

	select {
	case resp := <-resCh:
		// var resVal *proto.Message
		log.Debug("Received response from the worker")
		if resp.Data != nil && len(resp.ErrorMessage) == 0 && resp.ErrorStatus == commands.StatusCode_UNKNOWN {
			resp.ErrorStatus = commands.StatusCode_OK
		}

		data = resp.Data
		protoStatus.Code = int32(resp.ErrorStatus)
		protoStatus.Message = resp.ErrorMessage

	// we can wait up to 500ms to resolve request
	// todo: a way to cancel the request because even though it timeouts, the worker is still working on it
	case <-timeout:
		protoStatus.Code = int32(commands.StatusCode_REQUEST_TIMEOUT)
		protoStatus.Message = "Request took too long to resolve."
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
				log.Errorf("Error while creating response: %v", err)
				protoStatus.Code = int32(commands.StatusCode_PROCESSING_ERROR)
				protoStatus.Message = "Failed to marshal response"
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
				log.Errorf("Error while creating response: %v", err)
				protoStatus.Code = int32(commands.StatusCode_PROCESSING_ERROR)
				protoStatus.Message = "Failed to marshal response"
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
				Status: &commands.Status{
					Code:    int32(commands.StatusCode_UNAVAILABLE),
					Message: "The provider has not finished startup yet",
				},
			}
			log.Notice("Verification request to the server, while it has not finished startup (or data was nil)")
			// log.Critical("HAPPENED DURING CLIENT TESTS - nil data, NEED TO FIX WHEN CREATING SERVER TESTS!! (data is nil)")
		}
	case *commands.BlindSignRequest:
		protoBlindSig := &coconut.ProtoBlindedSignature{}
		if data != nil {
			protoBlindSig, err = data.(*coconut.BlindedSignature).ToProto()
			if err != nil {
				log.Errorf("Error while creating response: %v", err)
				protoStatus.Code = int32(commands.StatusCode_PROCESSING_ERROR)
				protoStatus.Message = "Failed to marshal response"
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
				Status: &commands.Status{
					Code:    int32(commands.StatusCode_UNAVAILABLE),
					Message: "The provider has not finished startup yet",
				},
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

func GetServerResponses(packet []byte, maxR int, log *logging.Logger, connT int, reqT int, addrs []string, ids []int) []*ServerResponse {
	responses := make([]*ServerResponse, len(addrs)) // can't possibly get more results
	respCh := make(chan *ServerResponse)
	reqCh := SendServerRequests(respCh, maxR, log, connT)

	// write requests in a goroutine so we wouldn't block when trying to read responses
	go func() {
		for i := range addrs {
			log.Debug("Writing request to %v", addrs[i])
			reqCh <- &ServerRequest{MarshaledData: packet, ServerAddress: addrs[i], ServerID: ids[i]}
		}
	}()

	WaitForServerResponses(respCh, responses, log, reqT)
	close(reqCh)
	return responses
}
