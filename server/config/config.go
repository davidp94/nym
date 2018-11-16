// config.go - config for coconut server
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

// Package config defines configuration used by coconut server.
package config

// todo: once all options are figured out, introduce validation

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
)

// todo: separate config entry for provider related things?

const (
	defaultLogLevel = "NOTICE"

	defaultNumCoconutWorkers = 1

	defaultConnectTimeout               = 5 * 1000  // 5 sec.
	defaultRequestTimeout               = 1 * 1000  // 1 sec.
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

	// Addresses are the IP address:port combinations that the server will bind	to for incoming connections.
	Addresses []string

	// Will definitely be useful later, but for now, no need for that.
	// // DataDir is the absolute path to the server's state files.
	// DataDir string

	// IsProvider specifies whether the server is a provider.
	// Currently it means it should be able to verify credentials it receives.
	IsProvider bool

	// IsIssuer specifies whether the server is a credential issuer.
	// Currently it means it should be able to sign attributes it receives.
	IsIssuer bool
}

type Issuer struct {
	// MaximumAttributes specifies the maximum number of attributes the server will sign.
	MaximumAttributes int

	// VerificationKeyFile specifies the file containing the Coconut Verification Key.
	VerificationKeyFile string

	// SecretKeyFile specifies the file containing the Coconut Secret Key.
	SecretKeyFile string
}

// todo: change name?
// Provider is the Coconut provider server configuration.
// At this point it is only responsible for verifying credentials it receives.
type Provider struct {
	// IAAddresses are the IP address:port combinations of all Authority Servers.
	// Required if the server is a provider.
	IAAddresses []string

	// IAIDs are IDs of the servers used during generation of threshold keys.
	// If empty, it is going to be assumed that IAAddresses are ordered correctly.
	IAIDs []int

	// Threshold defines minimum number of verification keys provider needs to obtain.
	// Default = len(IAAddresses).
	// 0 = no threshold
	Threshold int
}

// Debug is the Coconut IA server debug configuration.
type Debug struct {
	// NumJobWorkers specifies the number of worker instances to use for jobpacket processing.
	NumJobWorkers int

	// NumCoconutWorkers specifies the number of worker instances to use for client job requests.
	NumCoconutWorkers int

	// ConnectTimeout specifies the maximum time a connection can take to establish a TCP/IP connection in milliseconds.
	ConnectTimeout int

	// RequestTimeout specifies the maximum time a client job request can take to process.
	RequestTimeout int

	// RegenerateKeys specifies whether to generate new Coconut keypair and overwrite existing files.
	RegenerateKeys bool

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
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.NumJobWorkers <= 0 {
		dCfg.NumJobWorkers = runtime.NumCPU()
	}
	if dCfg.NumCoconutWorkers <= 0 {
		dCfg.NumCoconutWorkers = defaultNumCoconutWorkers
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

func (cfg *Config) validateAndApplyDefaults() error {
	if cfg.Server == nil {
		return errors.New("config: No Server block was present")
	}

	if !cfg.Server.IsProvider && !cfg.Server.IsIssuer {
		return errors.New("config: server is neither Issuer nor Provider")
	}
	if cfg.Server.IsProvider {
		if cfg.Provider == nil {
			return errors.New("config: Provider block not set when server is a Provider")
		}
		if len(cfg.Provider.IAIDs) <= 0 {
			IAIDs := make([]int, len(cfg.Provider.IAAddresses))
			for i := range cfg.Provider.IAAddresses {
				IAIDs[i] = i + 1
			}
		} else if len(cfg.Provider.IAIDs) != len(cfg.Provider.IAAddresses) || len(cfg.Provider.IAAddresses) <= 0 {
			return errors.New("config: Invalid provider - IA Servers configuration")
		}
	}

	if cfg.Server.IsIssuer {
		if cfg.Issuer == nil {
			return errors.New("config: Issuer block not set when server is an Issuer")
		}
		// does not care if files are empty, if so, new keys will be generated and written there
		if cfg.Issuer.SecretKeyFile == "" || cfg.Issuer.VerificationKeyFile == "" {
			return errors.New("config: No key files were provided")
		}
		if cfg.Issuer.MaximumAttributes <= 0 || cfg.Issuer.MaximumAttributes > 255 {
			return errors.New("config: Invalid number of allowed attributes")
		}
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

// LoadFile loads, parses and validates the provided file and returns the Config.
func LoadFile(f string) (*Config, error) {
	b, err := ioutil.ReadFile(filepath.Clean(f))
	if err != nil {
		return nil, err
	}
	cfg := new(Config)
	_, err = toml.Decode(string(b), cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.validateAndApplyDefaults(); err != nil {
		return nil, err
	}

	return cfg, nil
}
