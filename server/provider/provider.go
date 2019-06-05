package Foo

// // server.go - Coconut IA Server
// // Copyright (C) 2018-2019  Jedrzej Stuczynski.
// //
// // This program is free software: you can redistribute it and/or modify
// // it under the terms of the GNU Affero General Public License as
// // published by the Free Software Foundation, either version 3 of the
// // License, or (at your option) any later version.
// //
// // This program is distributed in the hope that it will be useful,
// // but WITHOUT ANY WARRANTY; without even the implied warranty of
// // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// // GNU Affero General Public License for more details.
// //
// // You should have received a copy of the GNU Affero General Public License
// // along with this program.  If not, see <http://www.gnu.org/licenses/>.

// // Package server defines structure for coconut IA server.
// package server

// import (
// 	"context"
// 	"errors"
// 	"fmt"
// 	"sync"
// 	"time"

// 	"0xacab.org/jstuczyn/CoconutGo/common/comm"
// 	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
// 	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobqueue"
// 	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
// 	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
// 	"0xacab.org/jstuczyn/CoconutGo/logger"
// 	"0xacab.org/jstuczyn/CoconutGo/server/config"
// 	grpclistener "0xacab.org/jstuczyn/CoconutGo/server/grpc/listener"
// 	"0xacab.org/jstuczyn/CoconutGo/server/listener"
// 	"0xacab.org/jstuczyn/CoconutGo/server/monitor"
// 	"0xacab.org/jstuczyn/CoconutGo/server/monitor/processor"
// 	"0xacab.org/jstuczyn/CoconutGo/server/requestqueue"
// 	"0xacab.org/jstuczyn/CoconutGo/server/serverworker"
// 	"0xacab.org/jstuczyn/CoconutGo/server/storage"
// 	nymclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
// 	"gopkg.in/op/go-logging.v1"
// )

// const (
// 	dbName = "serverStore"
// )

// // Server defines all the required attributes for a coconut server.
// type Server struct {
// 	cfg *config.Config

// 	// TODO: do we need to store all the keys and queues in the server struct?
// 	sk  *coconut.SecretKey
// 	vk  *coconut.VerificationKey
// 	avk *coconut.VerificationKey

// 	cmdCh *requestqueue.RequestQueue
// 	jobCh *jobqueue.JobQueue
// 	log   *logging.Logger

// 	serverWorkers []*serverworker.ServerWorker
// 	listeners     []*listener.Listener
// 	grpclisteners []*grpclistener.Listener
// 	jobWorkers    []*jobworker.JobWorker

// 	monitor    *monitor.Monitor
// 	processors []*processor.Processor
// 	store      *storage.Database

// 	haltedCh chan interface{}
// 	haltOnce sync.Once
// }

// // getIAsVerificationKeys gets verification keys of the issuers.
// // Returns at least threshold number of them or nil if it times out.
// func (s *Server) getIAsVerificationKeys() ([]*coconut.VerificationKey, *coconut.PolynomialPoints, error) {
// 	cmd, err := commands.NewVerificationKeyRequest()
// 	if err != nil {
// 		return nil, nil, comm.LogAndReturnError(s.log, "Failed to create Vk request: %v", err)
// 	}

// 	packetBytes, err := commands.CommandToMarshalledPacket(cmd)
// 	if err != nil {
// 		// should never happen...
// 		return nil, nil, comm.LogAndReturnError(s.log, "Could not create VK data packet: %v", err)
// 	}

// 	s.log.Notice("Going to send GetVK request to %v IAs", len(s.cfg.Provider.IAAddresses))

// 	responses := make([]*comm.ServerResponse, len(s.cfg.Provider.IAAddresses)) // can't possibly get more results
// 	retryTicker := time.NewTicker(time.Duration(s.cfg.Debug.ProviderStartupRetryInterval) * time.Millisecond)
// 	ctx, cancel := context.WithTimeout(
// 		context.Background(),
// 		time.Duration(s.cfg.Debug.ProviderStartupTimeout)*time.Millisecond,
// 	)
// 	defer cancel()

// 	// this allows to enter the case immediately, but in return timeout won't happen
// 	// exactly after ProviderStartupTimeout, but instead after N * ProviderStartupRetryInterval,
// 	// such that N * ProviderStartupRetryInterval > ProviderStartupTimeout, where N is a natural number.
// 	for ; true; <-retryTicker.C {
// 		s.log.Debug("Trying to obtain vks of all IAs...")
// 		// this is redone every run so that we would not get stale results
// 		responses = comm.GetServerResponses(
// 			ctx,
// 			&comm.RequestParams{
// 				MarshaledPacket:   packetBytes,
// 				MaxRequests:       s.cfg.Debug.ProviderMaxRequests,
// 				ConnectionTimeout: time.Duration(s.cfg.Debug.ConnectTimeout) * time.Millisecond,
// 				ServerAddresses:   s.cfg.Provider.IAAddresses,
// 				ServerIDs:         s.cfg.Provider.IAIDs,
// 			},
// 			s.log,
// 		)

// 		validResponses := 0
// 		for _, resp := range responses {
// 			if resp != nil {
// 				validResponses++
// 			}
// 		}

// 		if validResponses == len(s.cfg.Provider.IAAddresses) {
// 			s.log.Notice("Received Verification Keys from all IAs")
// 			break
// 		} else if validResponses >= s.cfg.Provider.Threshold && s.cfg.Provider.Threshold > 0 {
// 			s.log.Notice("Did not receive all verification keys, but got more than (or equal to) threshold of them")
// 			break
// 		} else {
// 			s.log.Noticef("Did not receive enough verification keys (%v out of minimum %v)",
// 				validResponses, s.cfg.Provider.Threshold)
// 		}

// 		select {
// 		case <-ctx.Done():
// 			s.log.Critical("Timed out while starting up...")
// 			return nil, nil, errors.New("startup timeout")
// 		default:
// 		}
// 	}
// 	retryTicker.Stop()

// 	vks, pp := comm.ParseVerificationKeyResponses(responses, s.cfg.Provider.Threshold > 0, s.log)
// 	vks, pp, err = comm.HandleVks(s.log, vks, pp, s.cfg.Provider.Threshold)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	if len(vks) >= s.cfg.Provider.Threshold && len(vks) > 0 && s.cfg.Provider.Threshold > 0 {
// 		s.log.Notice("Number of verification keys received is within threshold")
// 		vks = vks[:s.cfg.Provider.Threshold]
// 		pp = coconut.NewPP(pp.Xs()[:s.cfg.Provider.Threshold])
// 	} else if s.cfg.Provider.Threshold > 0 {
// 		return nil, nil, comm.LogAndReturnError(s.log, "Received less than threshold number of verification keys")
// 	}

// 	return vks, pp, nil
// }

// // New returns a new Server instance parameterized with the specified configuration.
// // nolint: gocyclo
// func New(cfg *config.Config) (*Server, error) {
// 	// there is no need to further validate it, as if it's not nil, it was already done
// 	if cfg == nil {
// 		return nil, errors.New("nil config provided")
// 	}

// 	log, err := logger.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create a logger: %v", err)
// 	}
// 	// without this, the servers during tests would have same id and would run into concurrency issues
// 	serverLog := log.GetLogger("Server - " + cfg.Server.Identifier)

// 	serverLog.Noticef("Logging level set to %v", cfg.Logging.Level)
// 	serverLog.Notice("Server's functionality: \nProvider:\t%v\nIA:\t\t%v", cfg.Server.IsProvider, cfg.Server.IsIssuer)

// 	jobCh := jobqueue.New()     // commands issued by coconutworkers, like do pairing, g1mul, etc
// 	cmdCh := requestqueue.New() // commands received via the socket, like sign those attributes

// 	var params *coconut.Params
// 	sk := &coconut.SecretKey{}
// 	vk := &coconut.VerificationKey{}
// 	var IAID uint32

// 	// if it's not an issuer, we don't care about own keys, because they are not going to be used anyway (for now).
// 	if cfg.Server.IsIssuer {
// 		IAID = cfg.Issuer.ID
// 		if cfg.Debug.RegenerateKeys {
// 			serverLog.Notice("Generating new sk/vk coconut keypair")
// 			params, err = coconut.Setup(cfg.Server.MaximumAttributes)
// 			if err != nil {
// 				return nil, err
// 			}
// 			serverLog.Debug("Generated params")

// 			sk, vk, err = coconut.Keygen(params)
// 			if err != nil {
// 				return nil, err
// 			}
// 			serverLog.Debug("Generated new keys")

// 			if sk.ToPEMFile(cfg.Issuer.SecretKeyFile) != nil || vk.ToPEMFile(cfg.Issuer.VerificationKeyFile) != nil {
// 				serverLog.Error("Couldn't write new keys to the files")
// 				return nil, errors.New("couldn't write new keys to the files")
// 			}

// 			serverLog.Notice("Written new keys to the files")
// 		} else {
// 			//nolint: govet
// 			if err := sk.FromPEMFile(cfg.Issuer.SecretKeyFile); err != nil {
// 				return nil, err
// 			}
// 			//nolint: govet
// 			if err := vk.FromPEMFile(cfg.Issuer.VerificationKeyFile); err != nil {
// 				return nil, err
// 			}
// 			if len(sk.Y()) > cfg.Server.MaximumAttributes || !coconut.ValidateKeyPair(sk, vk) {
// 				serverLog.Errorf("The loaded keys were invalid")
// 				return nil, errors.New("the loaded keys were invalid")
// 			}
// 			serverLog.Notice("Loaded Coconut server keys from the files.")

// 			// successfully loaded keys - create params of appropriate length
// 			params, err = coconut.Setup(len(sk.Y()))
// 			if err != nil {
// 				return nil, err
// 			}
// 		}
// 	} else {
// 		IAID = 0
// 		params, err = coconut.Setup(cfg.Server.MaximumAttributes)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}

// 	// if server is a provider we actually do need to keep the blockchain keys as we need to accept spend requests
// 	// and hence verify whether request is bound to our address
// 	// acc := account.Account{}
// 	if cfg.Server.IsProvider {
// 		if cfg.Provider.BlockchainKeysFile != "" {
// 			//nolint: govet
// 			// if err := acc.FromJSONFile(cfg.Provider.BlockchainKeysFile); err != nil {
// 			// 	errStr := fmt.Sprintf("Failed to load Nym keys: %v", err)
// 			// 	serverLog.Error(errStr)
// 			// 	return nil, errors.New(errStr)
// 			// }
// 			serverLog.Notice("Loaded Nym Blochain keys from the file.")
// 		} else {
// 			errStr := "no keys for the Nym Blockchain were specified while server is a provider"
// 			serverLog.Error(errStr)
// 			return nil, errors.New(errStr)
// 		}
// 	}

// 	var nymClient *nymclient.Client
// 	var store *storage.Database

// 	if !cfg.Debug.DisableAllBlockchainCommunication {
// 		serverLog.Warning("Blockchain communication is disabled - server will not communicate with blockchain at all")
// 		nymClient, err = nymclient.New(cfg.Server.BlockchainNodeAddresses, log)
// 		if err != nil {
// 			errStr := fmt.Sprintf("Failed to create a nymClient: %v", err)
// 			serverLog.Error(errStr)
// 			return nil, errors.New(errStr)
// 		}

// 		// store is currently only used if server is using a monitor
// 		store, err = storage.New(dbName, cfg.Server.DataDir)
// 		if err != nil {
// 			serverLog.Errorf("Failed to create a data store: %v", err)
// 			return nil, err
// 		}
// 	}

// 	avk := &coconut.VerificationKey{}

// 	serverWorkers := make([]*serverworker.ServerWorker, 0, cfg.Debug.NumServerWorkers)
// 	for i := 0; i < cfg.Debug.NumServerWorkers; i++ {
// 		serverWorkerCfg := &serverworker.Config{
// 			JobQueue:   jobCh.In(),
// 			IncomingCh: cmdCh.Out(),
// 			ID:         uint64(i + 1),
// 			Log:        log,
// 			Params:     params,
// 			IAID:       IAID,
// 			Sk:         sk,
// 			Vk:         vk,
// 			Avk:        avk,
// 			// NymAccount: acc,
// 			NymClient: nymClient,
// 			Store:     store,
// 		}
// 		serverWorker, nerr := serverworker.New(serverWorkerCfg)

// 		if nerr == nil {
// 			serverWorkers = append(serverWorkers, serverWorker)
// 		} else {
// 			serverLog.Errorf("Error while starting up serverWorker%v: %v", i, nerr)
// 		}
// 	}

// 	if len(serverWorkers) == 0 {
// 		errMsg := "could not start any server worker"
// 		serverLog.Critical(errMsg)
// 		return nil, errors.New(errMsg)
// 	}
// 	serverLog.Noticef("Started %v Server Worker(s)", cfg.Debug.NumServerWorkers)

// 	jobworkers := make([]*jobworker.JobWorker, cfg.Debug.NumJobWorkers)
// 	for i := range jobworkers {
// 		jobworkers[i] = jobworker.New(jobCh.Out(), uint64(i+1), log)
// 	}
// 	serverLog.Noticef("Started %v Job Worker(s)", cfg.Debug.NumJobWorkers)

// 	listeners := make([]*listener.Listener, len(cfg.Server.Addresses))
// 	for i, addr := range cfg.Server.Addresses {
// 		listeners[i], err = listener.New(cfg, cmdCh.In(), uint64(i+1), log, addr)
// 		if err != nil {
// 			serverLog.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
// 			return nil, err
// 		}
// 	}
// 	serverLog.Noticef("Started %v listener(s)", len(cfg.Server.Addresses))

// 	grpclisteners := make([]*grpclistener.Listener, len(cfg.Server.GRPCAddresses))
// 	for i, addr := range cfg.Server.GRPCAddresses {
// 		grpclisteners[i], err = grpclistener.New(cfg, cmdCh.In(), uint64(i+1), log, addr)
// 		if err != nil {
// 			serverLog.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
// 			return nil, err
// 		}
// 	}
// 	serverLog.Noticef("Started %v grpclistener(s)", len(cfg.Server.GRPCAddresses))

// 	var mon *monitor.Monitor
// 	processors := make([]*processor.Processor, cfg.Debug.NumProcessors)
// 	// there's no need for a provider to monitor the chain
// 	if cfg.Server.IsIssuer {
// 		if !cfg.Debug.DisableBlockchainMonitoring && !cfg.Debug.DisableAllBlockchainCommunication {
// 			mon, err = monitor.New(log, nymClient, store, int(IAID))
// 			if err != nil {
// 				// in theory we could still progress if chain comes back later on.
// 				// We will just have to catch up on the blocks
// 				serverLog.Errorf("Failed to spawn blockchain monitor")
// 			}
// 			serverLog.Noticef("Spawned blockchain monitor")
// 			for i := 0; i < cfg.Debug.NumProcessors; i++ {
// 				processor, err := processor.New(cmdCh.In(), mon, log, i, store)
// 				if err != nil {
// 					// but if we are unable to process the blocks, there's no point of the issuer
// 					serverLog.Critical("Failed to spawn blockchain block processor")
// 					return nil, err
// 				}
// 				processors[i] = processor
// 			}
// 			serverLog.Noticef("Spawned %v blockchain block processors", cfg.Debug.NumProcessors)
// 		}
// 	}

// 	s := &Server{
// 		cfg: cfg,

// 		sk: sk,
// 		vk: vk,

// 		cmdCh: cmdCh,
// 		jobCh: jobCh,
// 		log:   serverLog,

// 		serverWorkers: serverWorkers,
// 		listeners:     listeners,
// 		grpclisteners: grpclisteners,
// 		jobWorkers:    jobworkers,

// 		monitor:    mon,
// 		processors: processors,
// 		store:      store,

// 		haltedCh: make(chan interface{}),
// 	}

// 	// need to start trying to obtain vks of all IAs after starting listener in case other servers are also IA+provider
// 	if !cfg.Server.IsProvider {
// 		avk = nil
// 	} else {
// 		vks, pp, err := s.getIAsVerificationKeys()
// 		if err != nil {
// 			return nil, errors.New("failed to obtain verification keys of IAs")
// 		}

// 		*avk = *serverWorkers[0].AggregateVerificationKeysWrapper(vks, pp)
// 	}
// 	s.avk = avk

// 	for _, l := range s.listeners {
// 		l.FinalizeStartup()
// 	}
// 	for _, l := range s.grpclisteners {
// 		l.FinalizeStartup()
// 	}

// 	serverLog.Noticef("Started %v Server (Issuer: %v, Provider: %v)",
// 		cfg.Server.Identifier, cfg.Server.IsIssuer, cfg.Server.IsProvider)
// 	return s, nil
// }

// // Wait waits till the server is terminated for any reason.
// func (s *Server) Wait() {
// 	<-s.haltedCh
// }

// // Shutdown cleanly shuts down a given Server instance.
// func (s *Server) Shutdown() {
// 	s.haltOnce.Do(func() { s.halt() })
// }

// func (s *Server) halt() {
// 	s.log.Notice("Starting graceful shutdown.")

// 	for i, l := range s.grpclisteners {
// 		if l != nil {
// 			l.Halt()
// 			s.grpclisteners[i] = nil
// 		}
// 	}

// 	// Stop the listener(s), close all incoming connections.
// 	for i, l := range s.listeners {
// 		if l != nil {
// 			l.Halt() // Closes all connections.
// 			s.listeners[i] = nil
// 		}
// 	}

// 	for i, p := range s.processors {
// 		if p != nil {
// 			p.Halt()
// 			s.processors[i] = nil
// 		}
// 	}

// 	if s.monitor != nil {
// 		s.monitor.Halt()
// 		s.monitor = nil
// 	}

// 	for i, w := range s.serverWorkers {
// 		if w != nil {
// 			w.Halt()
// 			s.serverWorkers[i] = nil
// 		}
// 	}

// 	for i, w := range s.jobWorkers {
// 		if w != nil {
// 			w.Halt()
// 			s.jobWorkers[i] = nil
// 		}
// 	}

// 	if s.store != nil {
// 		s.store.Close()
// 		s.store = nil
// 	}

// 	s.log.Notice("Shutdown complete.")
// 	close(s.haltedCh)
// }
