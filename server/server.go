// server.go - Coconut IA Server
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

// Package server defines structure for coconut IA server.
package server

import (
	"errors"
	"sync"

	"github.com/eapache/channels"

	"github.com/jstuczyn/CoconutGo/logger"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutclient"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/server/config"
	"github.com/jstuczyn/CoconutGo/server/listener"

	"gopkg.in/op/go-logging.v1"
)

// Server defines all the required attributes for a coconut server.
type Server struct {
	cfg *config.Config

	sk *coconut.SecretKey
	vk *coconut.VerificationKey

	cmdCh *channels.InfiniteChannel
	jobCh *channels.InfiniteChannel

	log *logging.Logger

	coconutWorkers []*coconutclient.Worker
	listeners      []*listener.Listener
	jobWorkers     []*jobworker.Worker

	haltedCh chan interface{}
	haltOnce sync.Once
}

// New returns a new Server instance parameterized with the specified configuration.
func New(cfg *config.Config) (*Server, error) {
	var err error

	log := logger.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if log == nil {
		return nil, errors.New("Failed to create a logger")
	}
	serverLog := log.GetLogger("Server")

	// ensures that it IS displayed if any logging at all is enabled
	serverLog.Critical("Logging level set to %v", cfg.Logging.Level)

	jobCh := channels.NewInfiniteChannel() // commands issued by coconutworkers, like do pairing, g1mul, etc
	cmdCh := channels.NewInfiniteChannel() // commands received via the socket, like sign those attributes

	sk := &coconut.SecretKey{}
	vk := &coconut.VerificationKey{}

	var params *coconut.Params

	// todo: allow for empty verification key if secret key is set
	if cfg.Debug.RegenerateKeys || cfg.Server.SecretKeyFile == "" || cfg.Server.VerificationKeyFile == "" {
		serverLog.Notice("Generating new sk/vk coconut keypair")
		params, err = coconut.Setup(cfg.Server.MaximumAttributes)
		if err != nil {
			return nil, err
		}
		serverLog.Debug("Generated params")

		sk, vk, err = coconut.Keygen(params)
		if err != nil {
			return nil, err
		}
		serverLog.Debug("Generated new keys")

		if sk.ToPEMFile(cfg.Server.SecretKeyFile) != nil || vk.ToPEMFile(cfg.Server.VerificationKeyFile) != nil {
			serverLog.Error("Couldn't write new keys to the files")
			return nil, errors.New("Couldn't write new keys to the files")
		}

		serverLog.Notice("Written new keys to the files")
	} else {
		err = sk.FromPEMFile(cfg.Server.SecretKeyFile)
		if err != nil {
			return nil, err
		}
		err = vk.FromPEMFile(cfg.Server.VerificationKeyFile)
		if err != nil {
			return nil, err
		}
		if len(sk.Y()) != len(vk.Beta()) || len(sk.Y()) > cfg.Server.MaximumAttributes {
			serverLog.Errorf("Couldn't Load the keys")
			return nil, errors.New("The loaded keys were invalid. Delete the files and restart the server to regenerate them")
		}
		serverLog.Notice("Loaded Coconut server keys from the files.")
		// succesfully loaded keys - create params of appropriate length
		params, err = coconut.Setup(len(sk.Y()))
		if err != nil {
			return nil, err
		}
	}

	coconutworkers := make([]*coconutclient.Worker, cfg.Debug.NumCoconutWorkers)
	for i := range coconutworkers {
		coconutworkers[i] = coconutclient.New(jobCh.In(), cmdCh.Out(), uint64(i+1), log, params, sk, vk)
	}
	serverLog.Noticef("Started %v Coconut Worker(s)", cfg.Debug.NumCoconutWorkers)

	jobworkers := make([]*jobworker.Worker, cfg.Debug.NumJobWorkers)
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

	s := &Server{
		cfg: cfg,

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
	serverLog.Noticef("Started %v Server", cfg.Server.Identifier)
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

	s.log.Notice("Shutdown complete.")
	close(s.haltedCh)
}
