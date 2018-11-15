// set of helper functions used by both client and sever

package utils

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/jstuczyn/CoconutGo/server/commands"
	"github.com/jstuczyn/CoconutGo/server/packet"
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
func CommandToMarshaledPacket(cmd commands.Command, cmdID commands.CommandID) []byte {
	payloadBytes, err := cmd.MarshalBinary()
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
					return
				}

				conn.Write(req.MarshaledData)
				conn.SetReadDeadline(time.Now().Add(time.Duration(connectTimeout) * time.Millisecond))

				resp, err := ReadPacketFromConn(conn)
				if err != nil {
					log.Errorf("Received invalid response from %v: %v", req.ServerAddress, err)
					return
				} else {
					respCh <- &ServerResponse{MarshaledData: resp.Payload(), ServerID: req.ServerID, ServerAddress: req.ServerAddress}
				}
			}
		}()
	}
	return ch
}

func WaitForServerResponses(respCh <-chan *ServerResponse, responses []*ServerResponse, log *logging.Logger, requestTimeout int) {
	i := 0
	for {
		select {
		case resp := <-respCh:
			log.Debug("Received a reply from IA")
			responses[i] = resp
			i++

			if i == len(responses) {
				log.Debug("Got responses from all servers")
				return
			}
		case <-time.After(time.Duration(requestTimeout) * time.Millisecond):
			log.Notice("Timed out while sending requests")
			return
		}
	}
}
