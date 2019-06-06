// provider.go - Coconut Service Provider
// Copyright (C) 2019  Jedrzej Stuczynski.
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

// Package provider defines basic structure for a coconut Service Provider server.
package provider

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/common/comm"
	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobqueue"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	grpclistener "0xacab.org/jstuczyn/CoconutGo/server/grpc/listener"
	"0xacab.org/jstuczyn/CoconutGo/server/listener"
	"0xacab.org/jstuczyn/CoconutGo/server/monitor"
	"0xacab.org/jstuczyn/CoconutGo/server/monitor/processor"
	"0xacab.org/jstuczyn/CoconutGo/server/requestqueue"
	"0xacab.org/jstuczyn/CoconutGo/server/serverworker"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	nymclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"gopkg.in/op/go-logging.v1"
)

// Provider defines all the required attributes for a coconut provider.
type Provider struct {
	log   *logging.Logger
	haltOnce sync.Once
}

// New returns a new Server instance parameterized with the specified configuration.
// nolint: gocyclo
func New(cfg *config.Config) (*Server, error) {
	// there is no need to further validate it, as if it's not nil, it was already done
	if cfg == nil {
		return nil, errors.New("nil config provided")
	}

	log, err := logger.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		return nil, fmt.Errorf("failed to create a logger: %v", err)
	}
	// without this, the servers during tests would have same id and would run into concurrency issues
	providerLog := log.GetLogger("Provider - " + cfg.Server.Identifier)
	providerLog.Noticef("Logging level set to %v", cfg.Logging.Level)

	baseServer, err := server.New(cfg, log)
	if err != nil {
		return nil, err
	}

	if cfg.Provider.BlockchainKeysFile != "" {
		//nolint: govet
		// if err := acc.FromJSONFile(cfg.Provider.BlockchainKeysFile); err != nil {
		// 	errStr := fmt.Sprintf("Failed to load Nym keys: %v", err)
		// 	providerLog.Error(errStr)
		// 	return nil, errors.New(errStr)
		// }
		providerLog.Notice("Loaded Nym Blochain keys from the file.")
	} else {
		errStr := "no keys for the Nym Blockchain were specified while server is a provider"
		providerLog.Error(errStr)
		return nil, errors.New(errStr)
	}
	

	

	avk := &coconut.VerificationKey{}



	s := &Server{
		cfg: cfg,

		sk: sk,
		vk: vk,

		cmdCh: cmdCh,
		jobCh: jobCh,
		log:   providerLog,

		serverWorkers: serverWorkers,
		listeners:     listeners,
		grpclisteners: grpclisteners,
		jobWorkers:    jobworkers,

		monitor:    mon,
		processors: processors,
		store:      store,

		haltedCh: make(chan interface{}),
	}

	// need to start trying to obtain vks of all IAs after starting listener in case other servers are also IA+provider
	if !cfg.Server.IsProvider {
		avk = nil
	} else {
		vks, pp, err := s.getIAsVerificationKeys()
		if err != nil {
			return nil, errors.New("failed to obtain verification keys of IAs")
		}

		*avk = *serverWorkers[0].AggregateVerificationKeysWrapper(vks, pp)
	}
	s.avk = avk

	for _, l := range s.listeners {
		l.FinalizeStartup()
	}
	for _, l := range s.grpclisteners {
		l.FinalizeStartup()
	}

	providerLog.Noticef("Started %v Server (Issuer: %v, Provider: %v)",
		cfg.Server.Identifier, cfg.Server.IsIssuer, cfg.Server.IsProvider)
	return s, nil
}

// Wait waits till the server is terminated for any reason.
func (s *Server) Wait() {
	<-s.haltedCh
}

// Shutdown cleanly shuts down a given Server instance.
func (s *Server) Shutdown() {
	s.haltOnce.Do(func() { s.halt() })
}

func (s *Server) halt() {
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

	for i, p := range s.processors {
		if p != nil {
			p.Halt()
			s.processors[i] = nil
		}
	}

	if s.monitor != nil {
		s.monitor.Halt()
		s.monitor = nil
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
		s.store.Close()
		s.store = nil
	}

	s.log.Notice("Shutdown complete.")
	close(s.haltedCh)
}
