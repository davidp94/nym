// todo: change to server
package main

import (
	"github.com/eapache/channels"

	"github.com/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/CoconutGo/logger"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutclient"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/server/listener"

	"gopkg.in/op/go-logging.v1"
)

type Server struct {
	// todo: cfg ,etc
	sk *coconut.SecretKey
	vk *coconut.VerificationKey

	cmdCh *channels.InfiniteChannel
	jobCh *channels.InfiniteChannel

	log *logging.Logger

	coconutWorkers []*coconutclient.Worker
	listeners      []*listener.Listener
	jobWorkers     []*jobworker.Worker

	haltedCh chan interface{}
}

// TEMP, later will be moved to cfg
const NUM_WORKERS = 2
const NUM_COCONUT_WORKERS = 1
const NUM_LISTENERS = 1
const addr = "127.0.0.1:4000"

func New() (*Server, error) {
	var err error

	log := logger.New()
	serverLog := log.GetLogger("Server")

	jobCh := channels.NewInfiniteChannel() // commands issued by coconutworkers, like do pairing, g1mul, etc
	cmdCh := channels.NewInfiniteChannel() // commands received via the socket, like sign those attributes

	params, err := coconut.Setup(constants.SetupAttrs)
	if err != nil {
		panic(err)
	}
	serverLog.Debug("Generated params")

	sk, vk, _ := coconut.Keygen(params)
	serverLog.Debug("Generated keys")

	coconutworkers := make([]*coconutclient.Worker, NUM_COCONUT_WORKERS)
	for i := range coconutworkers {
		coconutworkers[i] = coconutclient.New(jobCh.In(), cmdCh.Out(), uint64(i+1), log, params, sk, vk)
	}
	serverLog.Debug("Started Coconut Workers")

	jobworkers := make([]*jobworker.Worker, NUM_WORKERS)
	for i := range jobworkers {
		jobworkers[i] = jobworker.New(jobCh.Out(), uint64(i+1), log)
	}

	serverLog.Debug("Started Job Workers")

	listeners := make([]*listener.Listener, NUM_LISTENERS)

	for i := range listeners {
		listeners[i], err = listener.New(cmdCh.In(), uint64(i+1), log, addr)
		if err != nil {
			serverLog.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
			return nil, err
		}
	}

	serverLog.Debug("Started Listener")

	s := &Server{
		sk:    sk,
		vk:    vk,
		cmdCh: cmdCh,
		jobCh: jobCh,
		log:   serverLog,

		coconutWorkers: coconutworkers,
		listeners:      listeners,
		jobWorkers:     jobworkers,

		haltedCh: make(chan interface{}),
	}
	return s, nil
}

// Wait waits till the server is terminated for any reason.
func (s *Server) Wait() {
	<-s.haltedCh
}

func (s *Server) halt() {
	s.log.Noticef("Starting graceful shutdown.")

	// Stop the listener(s), close all incoming connections.
	for i, l := range s.listeners {
		if l != nil {
			l.Halt() // Closes all connections.
			s.listeners[i] = nil
		}
	}

	for i, w := range s.coconutWorkers {
		if w != nil {
			w.Halt()
			s.coconutWorkers[i] = nil
		}
	}

	for i, w := range s.jobWorkers {
		if w != nil {
			w.Halt()
			s.jobWorkers[i] = nil
		}
	}

	s.log.Noticef("Shutdown complete.")
	close(s.haltedCh)
}

// also temp, later will be moved to daemon
func main() {
	s, err := New()
	if err != nil {
		panic(err)
	}
	<-s.haltedCh
}
