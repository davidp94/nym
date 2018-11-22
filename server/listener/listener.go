// listener.go - Coconut server listener.
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

// Package listener implements the support for incoming TCP connections.
package listener

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"

	"github.com/jstuczyn/CoconutGo/logger"
	"github.com/jstuczyn/CoconutGo/server/comm/utils"
	"github.com/jstuczyn/CoconutGo/server/commands"
	"github.com/jstuczyn/CoconutGo/server/config"
	"github.com/jstuczyn/CoconutGo/server/packet"

	"github.com/jstuczyn/CoconutGo/worker"
	"gopkg.in/op/go-logging.v1"
)

// todo: onnewconn in goroutine or something to not block on multiple clients

// Listener represents the Coconut Server listener (listening on TCP socket, not for gRPC via HTTP2)
type Listener struct {
	cfg *config.Config

	sync.Mutex
	worker.Worker

	log *logging.Logger

	incomingCh chan<- interface{}
	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup

	l net.Listener

	id uint64
}

// Halt stops the listener and closes (if any) connections.
func (l *Listener) Halt() {
	l.log.Debugf("Halting listener %d\n", l.id)
	err := l.l.Close()
	if err != nil {
		l.log.Noticef("%v", err)
	}
	l.Worker.Halt()

	// currently nothing is using the channels or wg anyway.
	close(l.closeAllCh)
	l.closeAllWg.Wait()
}

func (l *Listener) worker() {
	addr := l.l.Addr()
	l.log.Noticef("Listening on: %v", addr)
	defer func() {
		l.log.Noticef("Stopping listening on: %v", addr)
		err := l.l.Close()
		if err != nil {
			l.log.Noticef("%v", err)
		}
	}()
	for {
		conn, err := l.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		tcpConn := conn.(*net.TCPConn)
		if err = tcpConn.SetKeepAlive(true); err != nil {
			l.log.Errorf("Couldn't set TCP connection params", err)
		}
		if err = conn.SetDeadline(time.Now().Add(time.Duration(l.cfg.Debug.ConnectTimeout) * time.Millisecond)); err != nil {
			l.log.Errorf("Couldn't set TCP connection params", err)
		}

		l.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

		l.onNewConn(conn)
	}
}

func (l *Listener) onNewConn(conn net.Conn) {
	l.closeAllWg.Add(1)
	// todo deadlines etc
	defer func() {
		l.log.Debugf("Closing Connection to %v", conn.RemoteAddr())
		err := conn.Close()
		if err != nil {
			l.log.Noticef("%v", err)
		}

		// right now does not make any sense as listener does not deleage its work to anything
		// and is inherently single threaded (in terms of connections)
		l.closeAllWg.Done()
	}()

	l.log.Noticef("New Connection from %v", conn.RemoteAddr())
	inPacket, err := utils.ReadPacketFromConn(conn)
	if err != nil {
		l.log.Errorf("Failed to read received packet: %v", err)
		return
	}

	cmd, err := commands.FromBytes(inPacket.Payload())
	if err != nil {
		l.log.Errorf("Error while parsing packet: %v", err)
		return
	}
	resCh := make(chan *commands.Response, 1)
	cmdReq := commands.NewCommandRequest(cmd, resCh)

	l.incomingCh <- cmdReq
	outPacket := l.resolveCommand(cmd, resCh)
	l.replyToClient(outPacket, conn)
}

// nolint: interfacer
func (l *Listener) replyToClient(packet *packet.Packet, conn net.Conn) {
	l.log.Noticef("Replying back to the client (%v)", conn.RemoteAddr())
	b, err := packet.MarshalBinary()
	if err == nil {
		_, err = conn.Write(b)
		if err == nil {
			return
		}
	}

	l.log.Error("Couldn't reply to the client") // conn will close regardless after this
}

func (l *Listener) resolveCommand(cmd commands.Command, resCh chan *commands.Response) *packet.Packet {
	var data interface{}
	protoStatus := &commands.Status{}

	select {
	case resp := <-resCh:
		// var resVal *proto.Message
		l.log.Debug("Received response from the worker")
		if resp.Data != nil && len(resp.ErrorMessage) == 0 && resp.ErrorStatus == commands.StatusCode_UNKNOWN {
			resp.ErrorStatus = commands.StatusCode_OK
		}

		data = resp.Data
		protoStatus.Code = int32(resp.ErrorStatus)
		protoStatus.Message = resp.ErrorMessage

	// we can wait up to 500ms to resolve request
	// todo: a way to cancel the request because even though it timeouts, the worker is still working on it
	case <-time.After(time.Duration(l.cfg.Debug.RequestTimeout) * time.Millisecond):
		protoStatus.Code = int32(commands.StatusCode_REQUEST_TIMEOUT)
		protoStatus.Message = "Request took too long to resolve."
		l.log.Error("Failed to resolve request - timeout")
	}

	var protoResp proto.Message
	var err error
	switch cmd.(type) {
	case *commands.Sign:
		protoSig := &coconut.ProtoSignature{}
		if data != nil {
			protoSig, err = data.(*coconut.Signature).ToProto()
			if err != nil {
				l.log.Errorf("Error while creating response: %v", err)
				protoStatus.Code = int32(commands.StatusCode_PROCESSING_ERROR)
				protoStatus.Message = "Failed to marshal response"
			}

		}
		protoResp = &commands.SignResponse{
			Sig:    protoSig,
			Status: protoStatus,
		}
	case *commands.Vk:
		l.log.Fatal("NOT IMPLEMENTED")
	case *commands.Verify:
		l.log.Fatal("NOT IMPLEMENTED")
	case *commands.BlindSign:
		l.log.Fatal("NOT IMPLEMENTED")
	case *commands.BlindVerify:
		l.log.Fatal("NOT IMPLEMENTED")
	default:
		l.log.Fatal("NOT IMPLEMENTED")
		// return nil and dont reply
	}

	b, err := proto.Marshal(protoResp)
	if err != nil {
		l.log.Errorf("Error while marshaling proto response: %v", err)
		// we can't do much more with it anyway...
	}

	return packet.NewPacket(b)
}

// New creates a new listener.
func New(cfg *config.Config, inCh chan<- interface{}, id uint64, l *logger.Logger, addr string) (*Listener, error) {
	var err error

	listener := &Listener{
		cfg:        cfg,
		incomingCh: inCh,
		closeAllCh: make(chan interface{}),
		log:        l.GetLogger(fmt.Sprintf("Listener:%d", int(id))),
		id:         id,
	}

	listener.l, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	listener.Go(listener.worker)
	return listener, nil
}
