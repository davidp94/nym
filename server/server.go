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
	"time"

	"github.com/jstuczyn/CoconutGo/constants"

	"github.com/eapache/channels"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutclient"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/logger"
	"github.com/jstuczyn/CoconutGo/server/comm/utils"
	"github.com/jstuczyn/CoconutGo/server/commands"
	"github.com/jstuczyn/CoconutGo/server/config"
	"github.com/jstuczyn/CoconutGo/server/listener"

	"gopkg.in/op/go-logging.v1"
)

// todo: if provider AND issuer: ONLY accept getVK requests before completing startup

// Server defines all the required attributes for a coconut server.
type Server struct {
	cfg *config.Config

	sk  *coconut.SecretKey
	vk  *coconut.VerificationKey
	avk *coconut.VerificationKey

	cmdCh *channels.InfiniteChannel
	jobCh *channels.InfiniteChannel
	log   *logging.Logger

	coconutWorkers []*coconutclient.Worker
	listeners      []*listener.Listener
	jobWorkers     []*jobworker.Worker

	haltedCh chan interface{}
	haltOnce sync.Once
}

// GetIAsVerificationKeys gets verification keys of the issuers. Returns at least threshold number of them or nil if it times out.
func (s *Server) GetIAsVerificationKeys() ([]*coconut.VerificationKey, *coconut.PolynomialPoints) {
	maxRequests := s.cfg.Debug.ProviderMaxRequests
	if s.cfg.Debug.ProviderMaxRequests <= 0 {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

	cmd := commands.NewVk()
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.GetVerificationKeyID)
	if packetBytes == nil {
		s.log.Error("Could not create VK data packet") // should never happen...
		return nil, nil
	}

	s.log.Notice("Going to send GetVK request to %v IAs", len(s.cfg.Provider.IAAddresses))

	var closeOnce sync.Once

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
				defer func() {
					// in case the channel unexpectedly blocks (which should THEORETICALLY not happen),
					// the server won't crash
					if r := recover(); r != nil {
						s.log.Critical("Recovered: %v", r)
					}
				}()
				for i := range s.cfg.Provider.IAAddresses {
					if _, ok := receivedResponses[s.cfg.Provider.IAAddresses[i]]; !ok {
						s.log.Debug("Writing request to %v", s.cfg.Provider.IAAddresses[i])
						reqCh <- &utils.ServerRequest{MarshaledData: packetBytes, ServerAddress: s.cfg.Provider.IAAddresses[i], ServerID: s.cfg.Provider.IAIDs[i]}
					}
				}
				closeOnce.Do(func() { close(reqCh) }) // to terminate the goroutines after they are done
			}()
			utils.WaitForServerResponses(respCh, responses[len(receivedResponses):], s.log, s.cfg.Debug.RequestTimeout)
			closeOnce.Do(func() { close(reqCh) })

			for i := range responses {
				if responses[i] != nil {
					receivedResponses[responses[i].ServerAddress] = true
				}
			}

			if len(receivedResponses) == len(s.cfg.Provider.IAAddresses) {
				s.log.Notice("Received Verification Keys from all IAs")
				break outLoop
			} else if len(receivedResponses) >= s.cfg.Provider.Threshold {
				s.log.Notice("Did not receive all verification keys, but got more than (or equal to) threshold of them")
				break outLoop
			} else {
				s.log.Noticef("Did not receive enough verification keys (%v out of minimum %v)", len(receivedResponses), s.cfg.Provider.Threshold)
			}

		case <-timeout:
			s.log.Critical("Timed out while starting up...")
			return nil, nil
		}
	}
	retryTicker.Stop()

	vks, pp := utils.ParseVerificationKeyResponses(responses, s.cfg.Provider.Threshold > 0)

	if len(vks) >= s.cfg.Provider.Threshold && len(vks) > 0 {
		s.log.Notice("Number of verification keys received is within threshold")
	} else {
		s.log.Error("Received less than threshold number of verification keys")
		return nil, nil
	}

	return vks, pp
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
	serverLog.Notice("Server's functionality: \nProvider:\t%v\nIA:\t\t%v", cfg.Server.IsProvider, cfg.Server.IsIssuer)

	jobCh := channels.NewInfiniteChannel() // commands issued by coconutworkers, like do pairing, g1mul, etc
	cmdCh := channels.NewInfiniteChannel() // commands received via the socket, like sign those attributes

	sk := &coconut.SecretKey{}
	vk := &coconut.VerificationKey{}

	var params *coconut.Params

	// if it's not an issuer, we don't care about own keys, because they are not going to be used anyway (for now).
	if cfg.Server.IsIssuer {
		// todo: allow for empty verification key if secret key is set
		if cfg.Debug.RegenerateKeys || cfg.Issuer.SecretKeyFile == "" || cfg.Issuer.VerificationKeyFile == "" {
			serverLog.Notice("Generating new sk/vk coconut keypair")
			params, err = coconut.Setup(cfg.Issuer.MaximumAttributes)
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
			err = sk.FromPEMFile(cfg.Issuer.SecretKeyFile)
			if err != nil {
				return nil, err
			}
			err = vk.FromPEMFile(cfg.Issuer.VerificationKeyFile)
			if err != nil {
				return nil, err
			}
			if len(sk.Y()) != len(vk.Beta()) || len(sk.Y()) > cfg.Issuer.MaximumAttributes {
				serverLog.Errorf("Couldn't Load the keys")
				return nil, errors.New("The loaded keys were invalid. Delete the files and restart the server to regenerate them")
				// todo: check for g^Y() == Beta() for each i
			}
			serverLog.Notice("Loaded Coconut server keys from the files.")
			// succesfully loaded keys - create params of appropriate length
			params, err = coconut.Setup(len(sk.Y()))
			if err != nil {
				return nil, err
			}
		}
	} else {
		// even if it's not an issuer, it needs params to credential verification
		params, err = coconut.Setup(cfg.Issuer.MaximumAttributes)
		if err != nil {
			return nil, err
		}
	}

	avk := &coconut.VerificationKey{}

	coconutworkers := make([]*coconutclient.Worker, cfg.Debug.NumCoconutWorkers)
	for i := range coconutworkers {
		coconutworkers[i] = coconutclient.New(jobCh.In(), cmdCh.Out(), uint64(i+1), log, params, sk, vk, avk)
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

	if constants.ProtobufSerialization {
		serverLog.Info("Using protobuf for data serialization")
	} else {
		serverLog.Info("DEPRACATED: Using old method for data serialization")
	}

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

	// need to start trying to obtain vks of all IAs after starting listener in case other servers are also IA+provider
	if !cfg.Server.IsProvider {
		avk = nil
	} else {
		vks, pp := s.GetIAsVerificationKeys()
		if vks == nil {
			return nil, errors.New("Failed to obtain verification keys of IAs")
		}
		// todo: take a random worker if the are multiple
		// todo: nicer call to make the aggregate
		*avk = *coconutworkers[0].AggregateVerificationKeys(&coconutclient.MuxParams{Params: params, Mutex: sync.Mutex{}}, vks, pp)
	}
	s.avk = avk

	serverLog.Noticef("Started %v Server (Issuer: %v, Provider: %v)", cfg.Server.Identifier, cfg.Server.IsIssuer, cfg.Server.IsProvider)
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
