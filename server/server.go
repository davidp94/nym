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
	"fmt"
	"sync"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobqueue"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	grpclistener "0xacab.org/jstuczyn/CoconutGo/server/comm/grpc/listener"
	"0xacab.org/jstuczyn/CoconutGo/server/comm/requestqueue"
	"0xacab.org/jstuczyn/CoconutGo/server/comm/utils"
	"0xacab.org/jstuczyn/CoconutGo/server/commands"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	"0xacab.org/jstuczyn/CoconutGo/server/cryptoworker"
	"0xacab.org/jstuczyn/CoconutGo/server/listener"
	"gopkg.in/op/go-logging.v1"
)

// Server defines all the required attributes for a coconut server.
type Server struct {
	cfg *config.Config

	sk  *coconut.SecretKey
	vk  *coconut.VerificationKey
	avk *coconut.VerificationKey

	cmdCh *requestqueue.RequestQueue
	jobCh *jobqueue.JobQueue
	log   *logging.Logger

	cryptoWorkers []*cryptoworker.CryptoWorker
	listeners     []*listener.Listener
	grpclisteners []*grpclistener.Listener
	jobWorkers    []*jobworker.JobWorker

	haltedCh chan interface{}
	haltOnce sync.Once
}

// getIAsVerificationKeys gets verification keys of the issuers.
// Returns at least threshold number of them or nil if it times out.
func (s *Server) getIAsVerificationKeys() ([]*coconut.VerificationKey, *coconut.PolynomialPoints) {
	maxRequests := s.cfg.Debug.ProviderMaxRequests
	if s.cfg.Debug.ProviderMaxRequests <= 0 {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

	cmd, err := commands.NewVerificationKeyRequest()
	if err != nil {
		s.log.Errorf("Failed to create Vk request: %v", err)
		return nil, nil
	}

	packetBytes, err := commands.CommandToMarshaledPacket(cmd)
	if err != nil {
		s.log.Error("Could not create VK data packet: %v", err) // should never happen...
		return nil, nil
	}

	s.log.Notice("Going to send GetVK request to %v IAs", len(s.cfg.Provider.IAAddresses))

	responses := make([]*utils.ServerResponse, len(s.cfg.Provider.IAAddresses)) // can't possibly get more results
	respCh := make(chan *utils.ServerResponse)
	receivedResponses := make(map[string]bool)

	retryTicker := time.NewTicker(time.Duration(s.cfg.Debug.ProviderStartupRetryInterval) * time.Millisecond)
	timeout := time.After(time.Duration(s.cfg.Debug.ProviderStartupTimeout) * time.Millisecond)

outLoop:
	for {
		select {
		// todo: figure out how to enter the case immediately without waiting for first tick
		case <-retryTicker.C:
			// this is recreated every run so that we would not get stale results
			reqCh := utils.SendServerRequests(respCh, maxRequests, s.log, s.cfg.Debug.ConnectTimeout)

			// write requests in a goroutine so we wouldn't block when trying to read responses
			go func() {
				for i := range s.cfg.Provider.IAAddresses {
					if _, ok := receivedResponses[s.cfg.Provider.IAAddresses[i]]; !ok {
						s.log.Debug("Writing request to %v", s.cfg.Provider.IAAddresses[i])
						// TODO: can write to closed channel in certain situations (test with timeout at getvk)
						reqCh <- &utils.ServerRequest{
							MarshaledData: packetBytes,
							ServerMetadata: &utils.ServerMetadata{
								Address: s.cfg.Provider.IAAddresses[i],
								ID:      s.cfg.Provider.IAIDs[i],
							},
						}
					}
				}
			}()
			utils.WaitForServerResponses(respCh, responses[len(receivedResponses):], s.log, s.cfg.Debug.RequestTimeout)
			close(reqCh)

			for i := range responses {
				if responses[i] != nil {
					receivedResponses[responses[i].ServerMetadata.Address] = true
				}
			}

			if len(receivedResponses) == len(s.cfg.Provider.IAAddresses) {
				s.log.Notice("Received Verification Keys from all IAs")
				break outLoop
			} else if len(receivedResponses) >= s.cfg.Provider.Threshold {
				s.log.Notice("Did not receive all verification keys, but got more than (or equal to) threshold of them")
				break outLoop
			} else {
				s.log.Noticef("Did not receive enough verification keys (%v out of minimum %v)",
					len(receivedResponses), s.cfg.Provider.Threshold)
			}

		case <-timeout:
			s.log.Critical("Timed out while starting up...")
			return nil, nil
		}
	}
	retryTicker.Stop()

	vks, pp := utils.ParseVerificationKeyResponses(responses, s.cfg.Provider.Threshold > 0, s.log)

	if len(vks) >= s.cfg.Provider.Threshold && len(vks) > 0 {
		s.log.Notice("Number of verification keys received is within threshold")
	} else {
		s.log.Error("Received less than threshold number of verification keys")
		return nil, nil
	}

	return vks, pp
}

// New returns a new Server instance parameterized with the specified configuration.
// nolint: gocyclo
func New(cfg *config.Config) (*Server, error) {
	// there is no need to further validate it, as if it's not nil, it was already done
	if cfg == nil {
		return nil, errors.New("Nil config provided")
	}

	log, err := logger.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a logger: %v", err)
	}
	serverLog := log.GetLogger("Server")

	serverLog.Noticef("Logging level set to %v", cfg.Logging.Level)
	serverLog.Notice("Server's functionality: \nProvider:\t%v\nIA:\t\t%v", cfg.Server.IsProvider, cfg.Server.IsIssuer)

	jobCh := jobqueue.New()     // commands issued by coconutworkers, like do pairing, g1mul, etc
	cmdCh := requestqueue.New() // commands received via the socket, like sign those attributes

	var params *coconut.Params
	sk := &coconut.SecretKey{}
	vk := &coconut.VerificationKey{}

	// if it's not an issuer, we don't care about own keys, because they are not going to be used anyway (for now).
	if cfg.Server.IsIssuer {
		if cfg.Debug.RegenerateKeys {
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

			if sk.ToPEMFile(cfg.Issuer.SecretKeyFile) != nil || vk.ToPEMFile(cfg.Issuer.VerificationKeyFile) != nil {
				serverLog.Error("Couldn't write new keys to the files")
				return nil, errors.New("Couldn't write new keys to the files")
			}

			serverLog.Notice("Written new keys to the files")
		} else {
			if err := sk.FromPEMFile(cfg.Issuer.SecretKeyFile); err != nil {
				return nil, err
			}
			if err := vk.FromPEMFile(cfg.Issuer.VerificationKeyFile); err != nil {
				return nil, err
			}
			if len(sk.Y()) > cfg.Server.MaximumAttributes || !coconut.ValidateKeyPair(sk, vk) {
				serverLog.Errorf("The loaded keys were invalid")
				return nil, errors.New("The loaded keys were invalid")
			}
			serverLog.Notice("Loaded Coconut server keys from the files.")

			// successfully loaded keys - create params of appropriate length
			params, err = coconut.Setup(len(sk.Y()))
			if err != nil {
				return nil, err
			}
		}
	} else {
		params, err = coconut.Setup(cfg.Server.MaximumAttributes)
		if err != nil {
			return nil, err
		}
	}

	avk := &coconut.VerificationKey{}

	cryptoWorkers := make([]*cryptoworker.CryptoWorker, cfg.Debug.NumCryptoWorkers)
	for i := range cryptoWorkers {
		cryptoWorkerCfg := &cryptoworker.Config{
			JobQueue:   jobCh.In(),
			IncomingCh: cmdCh.Out(),
			ID:         uint64(i + 1),
			Log:        log,
			Params:     params,
			Sk:         sk,
			Vk:         vk,
			Avk:        avk,
		}
		cryptoWorkers[i] = cryptoworker.New(cryptoWorkerCfg)
	}
	serverLog.Noticef("Started %v Coconut Worker(s)", cfg.Debug.NumCryptoWorkers)

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

	grpclisteners := make([]*grpclistener.Listener, len(cfg.Server.GRPCAddresses))
	for i, addr := range cfg.Server.GRPCAddresses {
		grpclisteners[i], err = grpclistener.New(cfg, cmdCh.In(), uint64(i+1), log, addr)
		if err != nil {
			serverLog.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
			return nil, err
		}
	}
	serverLog.Noticef("Started %v grpclistener(s)", len(cfg.Server.GRPCAddresses))

	s := &Server{
		cfg: cfg,

		sk:    sk,
		vk:    vk,
		cmdCh: cmdCh,
		jobCh: jobCh,
		log:   serverLog,

		cryptoWorkers: cryptoWorkers,
		listeners:     listeners,
		grpclisteners: grpclisteners,
		jobWorkers:    jobworkers,

		haltedCh: make(chan interface{}),
	}

	// need to start trying to obtain vks of all IAs after starting listener in case other servers are also IA+provider
	if !cfg.Server.IsProvider {
		avk = nil
	} else {
		vks, pp := s.getIAsVerificationKeys()
		if vks == nil {
			return nil, errors.New("Failed to obtain verification keys of IAs")
		}
		*avk = *cryptoWorkers[0].AggregateVerificationKeysWrapper(vks, pp)
	}
	s.avk = avk

	for _, l := range s.listeners {
		l.FinalizeStartup()
	}
	for _, l := range s.grpclisteners {
		l.FinalizeStartup()
	}

	serverLog.Noticef("Started %v Server (Issuer: %v, Provider: %v)",
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

	for i, w := range s.cryptoWorkers {
		if w != nil {
			w.Halt()
			s.cryptoWorkers[i] = nil
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
