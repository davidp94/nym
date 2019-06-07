// config.go - config for coconut server
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

// Package config defines configuration used by coconut server.
package config

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
)

const (
	defaultLogLevel = "NOTICE"

	defaultNumServerWorkers = 1
	defaultNumProcessors    = 1

	defaultConnectTimeout               = 5 * 1000  // 5 sec.
	defaultRequestTimeout               = 5 * 1000  // 5 sec.
	defaultProviderStartupTimeout       = 30 * 1000 // 30 sec.
	defaultProviderStartupRetryInterval = 5 * 1000  // 5s.
	defaultProviderMaxRequests          = 16
)

// nolint: gochecknoglobals
var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Server is the Coconut IA server configuration.
type Server struct {
	// Identifier is the human readable identifier for the node.
	Identifier string

	// Addresses are the IP address:port combinations that the server will bind	to for incoming TCP connections.
	Addresses []string

	// GRPCAddresses are the IP address:port combinations that the server will bind	to for incoming grpcs.
	GRPCAddresses []string

	// DataDir specifies path to a .db file holding relevant server-specific persistent data.
	DataDir string

	// MaximumAttributes specifies the maximum number of attributes the system supports.
	MaximumAttributes int

	// BlockchainNodeAddresses specifies addresses of a blockchain nodes
	// to which the issuer should send all relevant requests.
	// Note that only a single request will ever be sent, but multiple addresses are provided in case
	// the particular node was unavailable.
	BlockchainNodeAddresses []string
}

// Issuer is the Coconut issuing authority server configuration.
// It is responsible for signing attributes it receives
// and providing its public verification key upon request.
type Issuer struct {
	// VerificationKeyFile specifies the file containing the Coconut Verification Key.
	VerificationKeyFile string

	// SecretKeyFile specifies the file containing the Coconut Secret Key.
	SecretKeyFile string
}

// Provider is the Coconut provider server configuration.
// At this point it is only responsible for verifying credentials it receives.
type Provider struct {
	// IAAddresses are the IP address:port combinations of all Authority Servers.
	// Only required if IAVerificationKeys is not specified.
	IAAddresses []string

	// IAVerificationKeys specifies files containing Coconut Verification keys of all Issuing Authorities.
	IAVerificationKeys []string

	// Threshold defines minimum number of verification keys provider needs to obtain.
	// Default = len(IAAddresses).
	// 0 = no threshold
	Threshold int

	// BlockchainKeyFile specifies the file containing the Blockchain relevant keys.
	BlockchainKeyFile string
}

// Debug is the Coconut IA server debug configuration.
type Debug struct {
	// NumJobWorkers specifies the number of worker instances to use for jobpacket processing.
	NumJobWorkers int

	// NumServerWorkers specifies the number of worker instances to use for client job requests.
	NumServerWorkers int

	// NumProcessors specifies the number of processor instances attached to the blockchain monitor.
	NumProcessors int

	// ConnectTimeout specifies the maximum time a connection can take to establish a TCP/IP connection in milliseconds.
	ConnectTimeout int

	// RequestTimeout specifies the maximum time a client job request can take to process.
	RequestTimeout int

	// ProviderStartupTimeout specifies how long the provider is going to keep retrying to start up before giving up.
	// Useful when all the servers are started at different orders.
	ProviderStartupTimeout int

	// ProviderStartupRetryInterval specifies retry interval for the provider during the start up.
	// Currently it involves retrying to obtain verification keys of all IAs.
	ProviderStartupRetryInterval int

	// MaxRequests defines maximum number of concurrent requests each provider can make.
	// only applicable to obtain verification keys of all IAs
	// -1 indicates no limit
	ProviderMaxRequests int

	// RegenerateKeys specifies whether to generate new Coconut keypair and overwrite existing files.
	RegenerateKeys bool

	// DisableAllBlockchainCommunication allows to disable startup of blockchain client, monitor and processor.
	// Not to be set in production environment. Only really applicable in tests.
	DisableAllBlockchainCommunication bool

	// DisableBlockchainMonitoring allows to disable startup of blockchain monitor and processor.
	// However, it does not disable a blockchain client so that server can still send transactions to the chain.
	// Not to be set in production environment. Only really applicable in tests.
	DisableBlockchainMonitoring bool
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.NumJobWorkers <= 0 {
		dCfg.NumJobWorkers = runtime.NumCPU()
	}
	if dCfg.NumServerWorkers <= 0 {
		dCfg.NumServerWorkers = defaultNumServerWorkers
	}
	if dCfg.NumProcessors <= 0 {
		dCfg.NumProcessors = defaultNumProcessors
	}
	if dCfg.ConnectTimeout <= 0 {
		dCfg.ConnectTimeout = defaultConnectTimeout
	}
	if dCfg.RequestTimeout <= 0 {
		dCfg.RequestTimeout = defaultRequestTimeout
	}
	if dCfg.ProviderStartupTimeout <= 0 {
		dCfg.ProviderStartupTimeout = defaultProviderStartupTimeout
	}
	if dCfg.ProviderStartupRetryInterval <= 0 {
		dCfg.ProviderStartupRetryInterval = defaultProviderStartupRetryInterval
	}
	if dCfg.ProviderMaxRequests <= 0 {
		dCfg.ProviderMaxRequests = defaultProviderMaxRequests
	}
}

// Logging is the Coconut IA server logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

// Config is the top level Coconut IA server configuration.
type Config struct {
	Server   *Server
	Logging  *Logging
	Issuer   *Issuer
	Provider *Provider
	Debug    *Debug
}

// nolint: gocyclo
func (cfg *Config) validateAndApplyDefaults() error {
	if cfg.Server == nil {
		return errors.New("config: No Server block was present")
	}
	if len(cfg.Server.Addresses) == 0 && len(cfg.Server.GRPCAddresses) == 0 {
		return errors.New("config: No addresses to bind the server to")
	}

	if cfg.Provider != nil {
		if len(cfg.Provider.IAAddresses) == 0 && len(cfg.Provider.IAVerificationKeys) == 0 {
			return errors.New("config: Invalid provider - IA Servers configuration")
		}
		if cfg.Provider.Threshold < 0 {
			return errors.New("config: Invalid threshold value")
		}
	}

	if cfg.Issuer != nil {
		// does not care if files are empty, if so, new keys will be generated and written there,
		// but explicitly needs both of them to be present
		if cfg.Issuer.SecretKeyFile == "" || cfg.Issuer.VerificationKeyFile == "" {
			return errors.New("config: No key files were provided")
		}
	}

	if cfg.Server.MaximumAttributes <= 0 || cfg.Server.MaximumAttributes > 255 {
		return errors.New("config: Invalid number of allowed attributes")
	}

	if len(cfg.Server.DataDir) == 0 {
		return errors.New("config: Unspecified DataDir")
	}

	if cfg.Debug == nil {
		cfg.Debug = &Debug{}
	}
	cfg.Debug.applyDefaults()

	if cfg.Logging == nil {
		cfg.Logging = &defaultLogging
	}

	return nil
}

// LoadBinary loads, parses and validates the provided buffer b (as a config)
// and returns the Config.
func LoadBinary(b []byte) (*Config, error) {
	cfg := new(Config)
	_, err := toml.Decode(string(b), cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validateAndApplyDefaults(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadFile loads, parses and validates the provided file and returns the Config.
func LoadFile(f string) (*Config, error) {
	b, err := ioutil.ReadFile(filepath.Clean(f))
	if err != nil {
		return nil, err
	}
	return LoadBinary(b)
}
