// set of helper functions used by both client and sever

package utils

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/golang/protobuf/proto"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/server/commands"
	"0xacab.org/jstuczyn/CoconutGo/server/packet"
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
	return packet.FromBytes(packetOutBytes), nil
}

// will be replaced/modified once whole thing is changed to use protobuf
// todo: should return nil if cmdID doesnt match cmd.
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

// todo: way to close all open conns on timeout
// used by both clients and providers
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
				}

				conn.Write(req.MarshaledData)
				conn.SetReadDeadline(time.Now().Add(time.Duration(connectTimeout) * time.Millisecond))

				resp, err := ReadPacketFromConn(conn)
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

func ResolveServerRequest(cmd commands.Command, resCh chan *commands.Response, log *logging.Logger, requestTimeout int) proto.Message {
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
		isValid := data.(bool)
		protoResp = &commands.VerifyResponse{
			IsValid: isValid,
			Status:  protoStatus,
		}
		log.Debugf("Was the received credential valid: %v", isValid)
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
		isValid := data.(bool)
		protoResp = &commands.BlindVerifyResponse{
			IsValid: isValid,
			Status:  protoStatus,
		}
		log.Debugf("Was the received credential valid: %v", isValid)
	default:
		log.Errorf("Received an unrecognized command.")
		return nil
	}
	return protoResp
}
