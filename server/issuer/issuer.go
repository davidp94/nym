// issuer.go - Coconut Issuing Authority
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

// Package issuer defines structure for coconut Issuing Authority.
package issuer

import (
	"errors"
	"fmt"
	"sync"

	monitor "0xacab.org/jstuczyn/CoconutGo/common/tendermintmonitor"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	processor "0xacab.org/jstuczyn/CoconutGo/server/issuer/tendermintprocessor"
	"gopkg.in/op/go-logging.v1"
)

// Issuer defines all the required attributes for a coconut issuer.
type Issuer struct {
	*server.BaseServer
	log        *logging.Logger
	monitor    *monitor.Monitor
	processors []*processor.Processor

	haltOnce sync.Once
}

// New returns a new Issuer instance parameterized with the specified configuration.
// nolint: gocyclo
func New(cfg *config.Config) (*Issuer, error) {
	// there is no need to further validate it, as if it's not nil, it was already done
	if cfg == nil {
		return nil, errors.New("nil config provided")
	}

	log, err := logger.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		return nil, fmt.Errorf("failed to create a logger: %v", err)
	}
	// without this, the servers during tests would have same id and would run into concurrency issues
	issuerLog := log.GetLogger("Issuer - " + cfg.Server.Identifier)
	issuerLog.Noticef("Logging level set to %v", cfg.Logging.Level)

	baseServer, err := server.New(cfg, log)
	if err != nil {
		return nil, err
	}

	tsk := &coconut.ThresholdSecretKey{}
	tvk := &coconut.ThresholdVerificationKey{}

	//nolint: govet
	if err := tsk.FromPEMFile(cfg.Issuer.SecretKeyFile); err != nil {
		return nil, err
	}
	//nolint: govet
	if err := tvk.FromPEMFile(cfg.Issuer.VerificationKeyFile); err != nil {
		return nil, err
	}

	if len(tsk.Y()) > cfg.Server.MaximumAttributes || !coconut.ValidateKeyPair(tsk.SecretKey, tvk.VerificationKey) {
		issuerLog.Errorf("The loaded keys were invalid")
		return nil, errors.New("the loaded keys were invalid")
	}
	issuerLog.Notice("Loaded Coconut server keys from the files.")

	for i, l := range baseServer.Listeners() {
		issuerLog.Debugf("Registering issuer handlers for listener %v", i)
		l.RegisterDefaultIssuerHandlers()
	}
	// for _, l := range baseServer.GrpcListeners() {
	// 	// TODO:
	// 	l.FinalizeStartup()
	// }

	errCount := 0
	for i, sw := range baseServer.ServerWorkers() {
		issuerLog.Debugf("Registering issuer handlers for serverworker %v", i)
		if err := sw.RegisterAsIssuer(tsk, tvk); err != nil {
			errCount++
			issuerLog.Warningf("Could not register worker %v as issuer", i)
		}
	}

	if errCount == len(baseServer.ServerWorkers()) {
		errMsg := "could not register any serverworker as issuer"
		issuerLog.Errorf(errMsg)
		return nil, errors.New(errMsg)
	}

	var mon *monitor.Monitor
	processors := make([]*processor.Processor, cfg.Debug.NumProcessors)

	if !cfg.Debug.DisableBlockchainMonitoring && !cfg.Debug.DisableAllBlockchainCommunication {
		mon, err = monitor.New(log, baseServer.NymClient(), baseServer.Store(), fmt.Sprintf("issur%v", tsk.ID()))
		if err != nil {
			// in theory we could still progress if chain comes back later on.
			// We will just have to catch up on the blocks
			issuerLog.Errorf("Failed to spawn blockchain monitor")
		}
		issuerLog.Noticef("Spawned blockchain monitor")
		for i := 0; i < cfg.Debug.NumProcessors; i++ {
			processor, err := processor.New(baseServer.CmdChIn(), mon, log, i, baseServer.Store())
			if err != nil {
				// but if we are unable to process the blocks, there's no point of the issuer
				issuerLog.Critical("Failed to spawn blockchain block processor")
				return nil, err
			}
			processors[i] = processor
		}
		issuerLog.Noticef("Spawned %v blockchain block processors", cfg.Debug.NumProcessors)
	}

	ia := &Issuer{
		BaseServer: baseServer,
		log:        issuerLog,
		monitor:    mon,
		processors: processors,
	}

	return ia, nil
}

// Shutdown cleanly shuts down a given Issuer instance.
func (ia *Issuer) Shutdown() {
	ia.haltOnce.Do(func() { ia.halt() })
}

func (ia *Issuer) halt() {
	ia.log.Notice("Starting graceful shutdown.")

	for i, p := range ia.processors {
		if p != nil {
			ia.log.Debugf("Stopping processor %v", i)
			p.Halt()
			ia.processors[i] = nil
		}
	}

	if ia.monitor != nil {
		ia.log.Debugf("Stopping Tendermint monitor")
		ia.monitor.Halt()
		ia.monitor = nil
	}

	ia.BaseServer.Shutdown()
}
