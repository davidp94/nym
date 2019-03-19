// listener.go - Coconut server gRPC listener.
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

// Package grpclistener implements the support for incoming gRPCs.
package grpclistener

import (
	"context"
	"fmt"
	"net"

	"0xacab.org/jstuczyn/CoconutGo/common/comm"
	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	pb "0xacab.org/jstuczyn/CoconutGo/common/grpc/services"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"gopkg.in/op/go-logging.v1"
)

// Listener represents the Coconut gRPC Server listener.
type Listener struct {
	cfg        *config.Config
	grpcServer *grpc.Server

	worker.Worker

	log *logging.Logger

	incomingCh chan<- *commands.CommandRequest

	l net.Listener

	id               uint64
	finalizedStartup bool
}

// ctx argument is required by the interface definition created by protobuf grpc.
// However, currently it is not being used in any way. Should this change? If so, how?

// BlindVerifyCredentials resolves the BlindVerifyRequest to verify a blind credential
// on a set of private and optional public attributes.
// nolint: lll
func (l *Listener) BlindVerifyCredentials(ctx context.Context, req *commands.BlindVerifyRequest) (*commands.BlindVerifyResponse, error) {
	blindVerifyResponse := l.resolveCommand(req).(*commands.BlindVerifyResponse)
	return blindVerifyResponse, nil
}

// BlindSignAttributes resolves the BlindSignRequest to issue a blind credential
// on a set of private and optional public attributes.
// nolint: lll
func (l *Listener) BlindSignAttributes(ctx context.Context, req *commands.BlindSignRequest) (*commands.BlindSignResponse, error) {
	blindSignResponse := l.resolveCommand(req).(*commands.BlindSignResponse)
	return blindSignResponse, nil
}

// VerifyCredentials resolves the VerifyRequest to verify a credential
// on a set of public attributes.
// nolint: lll
func (l *Listener) VerifyCredentials(ctx context.Context, req *commands.VerifyRequest) (*commands.VerifyResponse, error) {
	verifyResponse := l.resolveCommand(req).(*commands.VerifyResponse)
	return verifyResponse, nil
}

// GetVerificationKey resolves the VerificationKeyRequest to return
// server's public coconut verification key.
// nolint: lll
func (l *Listener) GetVerificationKey(ctx context.Context, req *commands.VerificationKeyRequest) (*commands.VerificationKeyResponse, error) {
	vkResponse := l.resolveCommand(req).(*commands.VerificationKeyResponse)
	return vkResponse, nil
}

// SignAttributes resolves the SignRequest to issue a credential
// on a set of public attributes.
func (l *Listener) SignAttributes(ctx context.Context, req *commands.SignRequest) (*commands.SignResponse, error) {
	signResponse := l.resolveCommand(req).(*commands.SignResponse)
	return signResponse, nil
}

func (l *Listener) resolveCommand(req proto.Message) proto.Message {
	resCh := make(chan *commands.Response, 1)
	cmdReq := commands.NewCommandRequest(req, resCh)
	l.incomingCh <- cmdReq

	return comm.ResolveServerRequest(req, resCh, l.log, l.cfg.Debug.RequestTimeout, l.finalizedStartup)
}

// Halt gracefully stops the listener.
func (l *Listener) Halt() {
	l.grpcServer.GracefulStop()
	l.Worker.Halt()
}

func (l *Listener) worker() {
	if err := l.grpcServer.Serve(l.l); err != nil {
		// if server failed it means there is a major issue somewhere
		// and the server should not be continuing its execution
		l.log.Fatalf("Serve failed: %v", err)
	}
}

// FinalizeStartup is used when the server is a provider. It indicates it has aggregated required
// number of verification keys and hence can verify received credentials.
func (l *Listener) FinalizeStartup() {
	l.finalizedStartup = true
}

// New creates new instance of a grpclistener using provided config and listening on specified address.
func New(cfg *config.Config, inCh chan<- *commands.CommandRequest, id uint64, l *logger.Logger, addr string) (*Listener, error) {
	var err error

	listener := &Listener{
		cfg:        cfg,
		incomingCh: inCh,
		log:        l.GetLogger(fmt.Sprintf("gRPCListener:%d", int(id))),
		id:         id,
		grpcServer: grpc.NewServer(),
	}

	listener.l, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	listener.log.Noticef("Listening on: %v", addr)

	if cfg.Server.IsIssuer {
		pb.RegisterIssuerServer(listener.grpcServer, listener)
		listener.log.Debug("Registered gRPC Service for Issuer")
	}
	if cfg.Server.IsProvider {
		pb.RegisterProviderServer(listener.grpcServer, listener)
		listener.log.Debug("Registered gRPC Service for Provider")
	}

	listener.Go(listener.worker)
	return listener, nil
}
