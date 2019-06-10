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
	"errors"
	"fmt"
	"sync"

	"0xacab.org/jstuczyn/CoconutGo/server"

	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"gopkg.in/op/go-logging.v1"
)

// Provider defines all the required attributes for a coconut provider.
type Provider struct {
	*server.BaseServer
	log *logging.Logger

	haltOnce sync.Once
}

func checkDuplicateID(ids []*Curve.BIG, id *Curve.BIG) bool {
	for _, el := range ids {
		if el == nil {
			continue
		}
		if Curve.Comp(el, id) == 0 {
			return true
		}
	}
	return false
}

func (prov *Provider) loadAndAggregateVerificationKeys(files, addresses []string, threshold int) (*coconut.VerificationKey, error) {
	if len(files) == 0 {
		if len(addresses) == 0 {
			prov.log.Error("No files or addresses specified")
			return nil, errors.New("no files or addresses specified")
		}

		// TODO: reimplement that
		return nil, errors.New("can't query IAs yet")
	}

	if len(files) < threshold {
		return nil, errors.New("insufficient number of keys provided")
	}

	vks := make([]*coconut.VerificationKey, threshold)
	xs := make([]*Curve.BIG, threshold)

	for i, f := range files {
		// no point in parsing more than threshold number of them
		if i == threshold {
			break
		}

		tvk := &coconut.ThresholdVerificationKey{}
		if err := tvk.FromPEMFile(f); err != nil {
			return nil, fmt.Errorf("failed to load key from file %v: %v", f, err)
		}
		idBIG := Curve.NewBIGint(int(tvk.ID()))
		if checkDuplicateID(xs, idBIG) {
			return nil, fmt.Errorf("at least two keys have the same id: %v", tvk.ID())
		}

		vks[i] = tvk.VerificationKey
		xs[i] = idBIG
	}

	// we have already started serverworkers, they're just not registered as providers yet,
	// but can perform crypto operations
	avk := prov.ServerWorkers()[0].AggregateVerificationKeysWrapper(vks, coconut.NewPP(xs))

	return avk, nil
}

// New returns a new Server instance parameterized with the specified configuration.
// nolint: gocyclo
func New(cfg *config.Config) (*Provider, error) {
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

	if cfg.Provider.BlockchainKeyFile == "" {
		errStr := "no keys for the Nym Blockchain were specified while server is a provider"
		providerLog.Error(errStr)
		return nil, errors.New(errStr)
	}

	privateKey, err := ethcrypto.LoadECDSA(cfg.Provider.BlockchainKeyFile)
	if err != nil {
		errStr := fmt.Sprintf("Failed to load Nym keys: %v", err)
		providerLog.Error(errStr)
		return nil, errors.New(errStr)
	}

	providerLog.Notice("Loaded Nym Blochain keys from the file.")

	// TODO: actually use the key:
	// - request/response to obtain address (required by client)
	// - send request to tendermint to redeem credential
	// - send request to tendermint to get paid

	provider := &Provider{
		BaseServer: baseServer,
		log:        providerLog,
	}

	avk, err := provider.loadAndAggregateVerificationKeys(cfg.Provider.IAVerificationKeys,
		cfg.Provider.IAAddresses,
		cfg.Provider.Threshold,
	)
	if err != nil {
		return nil, err
	}

	for i, l := range provider.Listeners() {
		providerLog.Debugf("Registering provider handlers for listener %v", i)
		l.RegisterDefaultServiceProviderHandlers()
	}
	// for _, l := range s.grpclisteners {
	// TODO:
	// 	l.FinalizeStartup()
	// }

	errCount := 0
	for i, sw := range provider.ServerWorkers() {
		providerLog.Debugf("Registering provider handlers for serverworker %v", i)
		if err := sw.RegisterAsProvider(avk, privateKey, cfg.Provider.DisableLocalCredentialsChecks); err != nil {
			errCount++
			providerLog.Warningf("Could not register worker %v as provider", i)
		}
	}

	if errCount == len(provider.ServerWorkers()) {
		errMsg := "could not register any serverworker as provider"
		providerLog.Errorf(errMsg)
		return nil, errors.New(errMsg)
	}

	return provider, nil
}

// Shutdown cleanly shuts down a given Provider instance.
func (prov *Provider) Shutdown() {
	prov.haltOnce.Do(func() { prov.halt() })
}

func (prov *Provider) halt() {
	prov.log.Notice("Starting graceful shutdown.")

	// currently no provider-specific procedures required

	prov.BaseServer.Shutdown()
}
