package grpclistener

import (
	"context"
	"fmt"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jstuczyn/CoconutGo/logger"
	pb "github.com/jstuczyn/CoconutGo/server/comm/grpc/services"
	"github.com/jstuczyn/CoconutGo/server/comm/utils"
	"github.com/jstuczyn/CoconutGo/server/commands"
	"github.com/jstuczyn/CoconutGo/server/config"
	"github.com/jstuczyn/CoconutGo/worker"
	"google.golang.org/grpc"
	"gopkg.in/op/go-logging.v1"
)

// todo: once the basic version is working,
// compare with normal listener and see if they could just be combined

type Listener struct {
	cfg        *config.Config
	grpcServer *grpc.Server
	worker.Worker

	log *logging.Logger

	incomingCh chan<- interface{}

	l net.Listener

	id uint64
}

// needed?
func (l *Listener) worker() {
	for {
		// ...
	}
}

func (l *Listener) DummyRpc(ctx context.Context, req *pb.DummyRequest) (*pb.DummyResponse, error) {
	return &pb.DummyResponse{
		Echo:  req.Hello,
		World: "World!",
	}, nil
}

func (l *Listener) SignAttributes(ctx context.Context, req *commands.SignRequest) (*commands.SignResponse, error) {
	// todo: do anything with ctx?
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

	pb.RegisterIssuerServer(listener.grpcServer, listener)
	listener.log.Debug("Registered gRPC Service")

	// if serve is not put in a gouroutine, server will block
	go func() {
		listener.grpcServer.Serve(listener.l)
	}()

	// listener.Go(listener.worker)
	return listener, nil
}
