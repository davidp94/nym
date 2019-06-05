// listener.go - Coconut server listener.
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

// Package listener implements the support for incoming TCP connections.
package listener

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/common/comm"
	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/common/comm/packet"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	"0xacab.org/jstuczyn/CoconutGo/server/listener/requesthandler"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"github.com/golang/protobuf/proto"
	"gopkg.in/op/go-logging.v1"
)

// Listener represents the Coconut Server listener (listening on TCP socket, not for gRPC via HTTP2)
// TODO: remove old fields and make more generic
type Listener struct {
	cfg *config.Config

	sync.Mutex
	worker.Worker

	log *logging.Logger

	incomingCh chan<- *commands.CommandRequest
	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup

	l  net.Listener
	id uint64

	handlers requesthandler.HandlerRegistry

	// DEPRECATED
	finalizedStartup bool
}

func (l *Listener) RegisterDefaultIssuerHandlers() {
	l.Lock()
	defer l.Unlock()
	// TODO: is there a better alternative for the way handlers are registered now?
	l.RegisterHandler(&commands.SignRequest{}, requesthandler.ResolveSignRequestHandler)
	l.RegisterHandler(&commands.BlindSignRequest{}, requesthandler.ResolveBlindSignRequestHandler)
	l.RegisterHandler(&commands.VerificationKeyRequest{}, requesthandler.ResolveVerificationKeyRequestHandler)
	l.RegisterHandler(&commands.LookUpCredentialRequest{}, requesthandler.ResolveLookUpCredentialRequestHandler)
	l.RegisterHandler(&commands.LookUpBlockCredentialsRequest{}, requesthandler.ResolveLookUpBlockCredentialsRequestHandler)
}

func (l *Listener) RegisterDefaultServiceProviderHandlers() {
	l.Lock()
	defer l.Unlock()
	// TODO: is there a better alternative for the way handlers are registered now?
	l.RegisterHandler(&commands.VerifyRequest{}, requesthandler.ResolveVerifyRequestHandler)
	l.RegisterHandler(&commands.BlindVerifyRequest{}, requesthandler.ResolveBlindVerifyRequestHandler)
	l.RegisterHandler(&commands.SpendCredentialRequest{}, requesthandler.ResolveSpendCredentialRequestHandler)
}

func (l *Listener) RegisterHandler(o interface{}, hf requesthandler.ResolveRequestHandlerFunc) {
	typ := reflect.TypeOf(o)
	if _, ok := l.handlers[typ]; ok {
		l.log.Warningf("%v already had a registered handler. It will be overritten", typ)
	}
	l.log.Debugf("Registering handler for %v", typ)

	l.handlers[typ] = hf
}

// Halt stops the listener and closes (if any) connections.
func (l *Listener) Halt() {
	l.log.Debugf("Halting listener %d\n", l.id)
	if err := l.l.Close(); err != nil {
		l.log.Noticef("%v", err)
	}
	l.Worker.Halt()

	// currently nothing is using the channel yet anyway.
	close(l.closeAllCh)
	l.closeAllWg.Wait()
}

func (l *Listener) worker() {
	addr := l.l.Addr()
	l.log.Noticef("Listening on: %v", addr)
	defer func() {
		l.log.Noticef("Stopping listening on: %v", addr)
		if err := l.l.Close(); err != nil {
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

		go func() {
			// TODO: maximum number of concurrent connections
			l.onNewConn(conn)
		}()
	}
}

func (l *Listener) onNewConn(conn net.Conn) {
	l.closeAllWg.Add(1)
	defer func() {
		l.log.Debugf("Closing Connection to %v", conn.RemoteAddr())
		err := conn.Close()
		if err != nil {
			l.log.Noticef("%v", err)
		}

		l.closeAllWg.Done()
	}()

	l.log.Noticef("New Connection from %v", conn.RemoteAddr())
	inPacket, err := comm.ReadPacketFromConn(conn)
	if err != nil {
		l.log.Errorf("Failed to read received packet: %v", err)
		return
	}

	cmd, err := commands.FromBytes(inPacket.Payload())
	if err != nil {
		l.log.Errorf("Error while parsing packet: %v", err)
		return
	}

	if _, ok := l.handlers[reflect.TypeOf(cmd)]; !ok {
		l.log.Warningf("There's no registered handler for %v", reflect.TypeOf(cmd))
		// TODO: write meaningful 'error' data back to client
		l.replyToClient(packet.NewPacket([]byte{}), conn)
		return
	}
	resCh := make(chan *commands.Response, 1)
	cmdReq := commands.NewCommandRequest(cmd, resCh)

	l.incomingCh <- cmdReq
	outPacket := l.resolveCommand(cmd, resCh)
	if outPacket != nil {
		l.replyToClient(outPacket, conn)
	}
}

//nolint: interfacer
func (l *Listener) replyToClient(packet *packet.Packet, conn net.Conn) {
	l.log.Noticef("Replying back to the client (%v)", conn.RemoteAddr())
	b, err := packet.MarshalBinary()
	if err == nil {
		if _, err = conn.Write(b); err == nil {
			return
		}
	}

	l.log.Error("Couldn't reply to the client") // conn will close regardless after this
}

func (l *Listener) resolveCommand(cmd commands.Command, resCh chan *commands.Response) *packet.Packet {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(l.cfg.Debug.RequestTimeout)*time.Millisecond)
	defer cancel()

	protoResp := l.handlers[reflect.TypeOf(cmd)](ctx, resCh)
	// protoResp := comm.ResolveServerRequest(cmd, resCh, l.log, l.cfg.Debug.RequestTimeout, l.finalizedStartup)

	b, err := proto.Marshal(protoResp)
	if err != nil {
		l.log.Errorf("Error while marshaling proto response: %v", err)
		// we can't do much more with it anyway...
	}

	return packet.NewPacket(b)
}

// FinalizeStartup is used when the server is a provider. It indicates it has aggregated required
// number of verification keys and hence can verify received credentials.
// TODO: get rid in favour of simply loading all keys on startup
func (l *Listener) FinalizeStartup() {
	l.finalizedStartup = true
}

// New creates a new listener.
func New(cfg *config.Config, inCh chan<- *commands.CommandRequest, id uint64, l *logger.Logger, addr string,
) (*Listener, error) {
	var err error

	listener := &Listener{
		cfg:        cfg,
		incomingCh: inCh,
		closeAllCh: make(chan interface{}),
		log:        l.GetLogger(fmt.Sprintf("Listener:%d", int(id))),
		id:         id,
		handlers:   make(requesthandler.HandlerRegistry),
	}

	listener.l, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	listener.Go(listener.worker)
	return listener, nil
}
