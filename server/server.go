// server.go - Coconut IA Server
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

// Package server defines structure for coconut IA server.
package server

import (
	"errors"
	"fmt"
	"sync"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobqueue"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	grpclistener "0xacab.org/jstuczyn/CoconutGo/server/grpc/listener"
	"0xacab.org/jstuczyn/CoconutGo/server/listener"
	"0xacab.org/jstuczyn/CoconutGo/server/requestqueue"
	"0xacab.org/jstuczyn/CoconutGo/server/serverworker"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	nymclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"gopkg.in/op/go-logging.v1"
)

const (
	dbName = "serverStore"
)

// BaseServer defines all the required attributes for a coconut server.
type BaseServer struct {
	log           *logging.Logger
	cmdCh         *requestqueue.RequestQueue
	serverWorkers []*serverworker.ServerWorker
	listeners     []*listener.Listener
	grpclisteners []*grpclistener.Listener
	jobWorkers    []*jobworker.JobWorker
	store         *storage.Database
	nymClient     *nymclient.Client
	haltedCh      chan interface{}
	haltOnce      sync.Once
}

func (s *BaseServer) NymClient() *nymclient.Client {
	return s.nymClient
}

func (s *BaseServer) Store() *storage.Database {
	return s.store
}

func (s *BaseServer) CmdChIn() chan<- *commands.CommandRequest {
	return s.cmdCh.In()
}

func (s *BaseServer) Listeners() []*listener.Listener {
	return s.listeners
}

func (s *BaseServer) GrpcListeners() []*grpclistener.Listener {
	return s.grpclisteners
}

func (s *BaseServer) ServerWorkers() []*serverworker.ServerWorker {
	return s.serverWorkers
}

// New returns a new Server instance parameterized with the specified configuration.
// nolint: gocyclo
func New(cfg *config.Config, log *logger.Logger) (*BaseServer, error) {
	// there is no need to further validate it, as if it's not nil, it was already done
	if cfg == nil {
		return nil, errors.New("nil config provided")
	}
	serverLog := log.GetLogger("BaseServer - " + cfg.Server.Identifier)

	jobCh := jobqueue.New()     // commands issued by coconutworkers, like do pairing, g1mul, etc
	cmdCh := requestqueue.New() // commands received via the socket, like sign those attributes

	params, err := coconut.Setup(cfg.Server.MaximumAttributes)
	if err != nil {
		return nil, err
	}

	var nymClient *nymclient.Client
	var store *storage.Database

	if cfg.Debug.DisableAllBlockchainCommunication {
		serverLog.Warning("Blockchain communication is disabled - server will not communicate with blockchain at all")
	} else {
		nymClient, err = nymclient.New(cfg.Server.BlockchainNodeAddresses, log)
		if err != nil {
			errStr := fmt.Sprintf("Failed to create a nymClient: %v", err)
			serverLog.Error(errStr)
			return nil, errors.New(errStr)
		}
	}

	// store is currently only used if server is using a monitor
	store, err = storage.New(dbName, cfg.Server.DataDir)
	if err != nil {
		serverLog.Errorf("Failed to create a data store: %v", err)
		return nil, err
	}

	serverWorkers := make([]*serverworker.ServerWorker, 0, cfg.Debug.NumServerWorkers)
	for i := 0; i < cfg.Debug.NumServerWorkers; i++ {
		serverWorkerCfg := &serverworker.Config{
			JobQueue:   jobCh.In(),
			IncomingCh: cmdCh.Out(),
			ID:         uint64(i + 1),
			Log:        log,
			Params:     params,
			NymClient:  nymClient,
			Store:      store,
		}
		serverWorker, nerr := serverworker.New(serverWorkerCfg)

		if nerr == nil {
			serverWorkers = append(serverWorkers, serverWorker)
		} else {
			serverLog.Errorf("Error while starting up serverWorker%v: %v", i, nerr)
		}
	}

	if len(serverWorkers) == 0 {
		errMsg := "could not start any server worker"
		serverLog.Critical(errMsg)
		return nil, errors.New(errMsg)
	}
	serverLog.Noticef("Started %v Server Worker(s)", cfg.Debug.NumServerWorkers)

	jobworkers := make([]*jobworker.JobWorker, cfg.Debug.NumJobWorkers)
	for i := range jobworkers {
		jobworkers[i] = jobworker.New(jobCh.Out(), uint64(i+1), log)
	}
	serverLog.Noticef("Started %v Job Worker(s)", cfg.Debug.NumJobWorkers)

	listeners := make([]*listener.Listener, len(cfg.Server.Addresses))
	for i, addr := range cfg.Server.Addresses {
		listeners[i], err = listener.New(cfg, cmdCh.In(), uint64(i+1), log, addr)
		if err != nil {
			serverLog.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
			return nil, err
		}
	}
	serverLog.Noticef("Started %v listener(s)", len(cfg.Server.Addresses))

	// TODO: FIXME: deal with the grpc listeners
	grpclisteners := make([]*grpclistener.Listener, len(cfg.Server.GRPCAddresses))
	// for i, addr := range cfg.Server.GRPCAddresses {
	// 	grpclisteners[i], err = grpclistener.New(cfg, cmdCh.In(), uint64(i+1), log, addr)
	// 	if err != nil {
	// 		serverLog.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
	// 		return nil, err
	// 	}
	// }
	// serverLog.Noticef("Started %v grpclistener(s)", len(cfg.Server.GRPCAddresses))

	s := &BaseServer{
		log:           serverLog,
		cmdCh:         cmdCh,
		serverWorkers: serverWorkers,
		listeners:     listeners,
		grpclisteners: grpclisteners,
		jobWorkers:    jobworkers,
		store:         store,
		nymClient:     nymClient,
		haltedCh:      make(chan interface{}),
	}

	serverLog.Noticef("Started %v Base Server ", cfg.Server.Identifier)
	return s, nil
}

// Wait waits till the server is terminated for any reason.
func (s *BaseServer) Wait() {
	<-s.haltedCh
}

// Shutdown cleanly shuts down a given Server instance.
func (s *BaseServer) Shutdown() {
	s.haltOnce.Do(func() { s.halt() })
}

func (s *BaseServer) halt() {
	s.log.Notice("Starting graceful shutdown.")

	for i, l := range s.grpclisteners {
		if l != nil {
			l.Halt()
			s.grpclisteners[i] = nil
		}
	}

	// Stop the listener(s), close all incoming connections.
	for i, l := range s.listeners {
		if l != nil {
			l.Halt() // Closes all connections.
			s.listeners[i] = nil
		}
	}

	for i, w := range s.serverWorkers {
		if w != nil {
			w.Halt()
			s.serverWorkers[i] = nil
		}
	}

	for i, w := range s.jobWorkers {
		if w != nil {
			w.Halt()
			s.jobWorkers[i] = nil
		}
	}

	if s.store != nil {
		s.log.Debugf("Closing datastore")
		s.store.Close()
		s.store = nil
	}

	s.log.Notice("Shutdown complete.")
	close(s.haltedCh)
}
