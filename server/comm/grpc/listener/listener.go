package grpclistener

import (
	"context"
	"fmt"
	"net"

	"0xacab.org/jstuczyn/CoconutGo/logger"
	pb "0xacab.org/jstuczyn/CoconutGo/server/comm/grpc/services"
	"0xacab.org/jstuczyn/CoconutGo/server/comm/utils"
	"0xacab.org/jstuczyn/CoconutGo/server/commands"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"gopkg.in/op/go-logging.v1"
)

// todo: once the basic version is working,
// compare with normal listener and see if they could just be combined

type Listener struct {
	cfg        *config.Config
	grpcServer *grpc.Server

	log *logging.Logger

	incomingCh chan<- interface{}

	l net.Listener

	id uint64
}

func (l *Listener) BlindVerifyCredentials(ctx context.Context, req *commands.BlindVerifyRequest) (*commands.BlindVerifyResponse, error) {
	// todo: do anything with ctx?
	blindVerifyResponse := l.resolveCommand(req).(*commands.BlindVerifyResponse)
	return blindVerifyResponse, nil
}

func (l *Listener) BlindSignAttributes(ctx context.Context, req *commands.BlindSignRequest) (*commands.BlindSignResponse, error) {
	// todo: do anything with ctx?
	blindSignResponse := l.resolveCommand(req).(*commands.BlindSignResponse)
	return blindSignResponse, nil
}

func (l *Listener) VerifyCredentials(ctx context.Context, req *commands.VerifyRequest) (*commands.VerifyResponse, error) {
	// todo: do anything with ctx?
	verifyResponse := l.resolveCommand(req).(*commands.VerifyResponse)
	return verifyResponse, nil
}

func (l *Listener) GetVerificationKey(ctx context.Context, req *commands.VerificationKeyRequest) (*commands.VerificationKeyResponse, error) {
	// todo: do anything with ctx?
	vkResponse := l.resolveCommand(req).(*commands.VerificationKeyResponse)
	return vkResponse, nil
}

func (l *Listener) SignAttributes(ctx context.Context, req *commands.SignRequest) (*commands.SignResponse, error) {
	signResponse := l.resolveCommand(req).(*commands.SignResponse)
	return signResponse, nil
}

func (l *Listener) resolveCommand(req proto.Message) proto.Message {
	resCh := make(chan *commands.Response, 1)
	cmdReq := commands.NewCommandRequest(req, resCh)
	l.incomingCh <- cmdReq

	return utils.ResolveServerRequest(req, resCh, l.log, l.cfg.Debug.RequestTimeout)
}

func (l *Listener) Halt() {
	l.grpcServer.GracefulStop()
}

func New(cfg *config.Config, inCh chan<- interface{}, id uint64, l *logger.Logger, addr string) (*Listener, error) {
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

	// if serve is not put in a gouroutine, server will block
	go func() {
		listener.grpcServer.Serve(listener.l)
	}()

	return listener, nil
}
