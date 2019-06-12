// config.go - config for Nym verifier
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

// Package config defines configuration used by Nym verifier.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
)

const (
	defaultLogLevel = "NOTICE"

	defaultNumServerWorkers = 1
)

// nolint: gochecknoglobals
var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Verifier is the main Nym verifier configuration.
type Verifier struct {
	// Identifier is the human readable identifier for the node.
	Identifier string

	// KeyFile defines path to file containing ECDSA private key of the verifier.
	KeyFile string

	// DataDir specifies path to a .db file holding relevant server-specific persistent data.
	DataDir string

	// MaximumAttributes specifies the maximum number of attributes the system supports.
	MaximumAttributes int

	// BlockchainNodeAddresses specifies addresses of a blockchain nodes
	// to which the issuer should send all relevant requests.
	// Note that only a single request will ever be sent, but multiple addresses are provided in case
	// the particular node was unavailable.
	BlockchainNodeAddresses []string

	// IAAddresses are the IP address:port combinations of all Authority Servers.
	// Only required if IAVerificationKeys is not specified.
	IAAddresses []string

	// IAVerificationKeys specifies files containing Coconut Verification keys of all Issuing Authorities.
	IAVerificationKeys []string

	// Threshold defines the threshold parameter of the system indicating number of keys needed for aggregation.
	Threshold int
}

// Debug is the Nym verifier debug configuration.
type Debug struct {
	// NumJobWorkers specifies the number of worker instances to use for jobpacket processing.
	NumJobWorkers int

	// NumServerWorkers specifies the number of concurrent worker instances
	// to use when processing verification requests.
	NumServerWorkers int
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.NumJobWorkers <= 0 {
		dCfg.NumJobWorkers = runtime.NumCPU()
	}
	if dCfg.NumServerWorkers <= 0 {
		dCfg.NumServerWorkers = defaultNumServerWorkers
	}
}

// Logging is the Nym verifier logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

// Config is the top level Nym verifier configuration.
type Config struct {
	Verifier *Verifier
	Logging  *Logging
	Debug    *Debug
}

// nolint: gocyclo
func (cfg *Config) validateAndApplyDefaults() error {
	if cfg.Verifier == nil {
		return errors.New("config: No Verifier block was present")
	}

	if _, err := os.Stat(cfg.Verifier.KeyFile); err != nil {
		return fmt.Errorf("config: The specified key file does not seem to exist: %v", err)
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
