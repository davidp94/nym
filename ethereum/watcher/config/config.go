// config.go - config for Ethereum watcher
// Copyright (C) 2019  Dave Hrycyszyn and Jedrzej Stuczynski.
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

// Package config defines configuration used by Ethereum watcher.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const (
	defaultLogLevel = "NOTICE"

	defaultNumConfirmations = 13
)

// nolint: gochecknoglobals
var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Watcher is the main Ethereum watcher configuration.
type Watcher struct {
	// KeyFile defines path to file containing ECDSA private key of the watcher.
	KeyFile string
	// EthereumNodeAddress defines address of the Ethereum node that the watcher is monitoring.
	EthereumNodeAddress string
	// NymContract defined address of the ERC20 token Nym contract. It is expected to be provided in hex format.
	NymContract string
	// PipeAccount defines address of Ethereum account that pipes Nym ERC20 into Nym Tendermint coins.
	// It is expected to be provided in hex format.
	PipeAccount string
}

// Debug is the Ethereum watcher debug configuration.
type Debug struct {
	// NumConfirmations defines number blocks we should wait before considering Ethereum to be final.
	NumConfirmations int64
}

func (dCfg *Debug) applyDefaults() {
	// TODO: should we allow '0' for test sake?
	if dCfg.NumConfirmations <= 0 {
		dCfg.NumConfirmations = defaultNumConfirmations
	}
}

// Logging is the Ethereum watcher logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

// Config is the top level Ethereum watcher configuration.
type Config struct {
	Watcher *Watcher
	Logging *Logging
	Debug   *Debug
}

// nolint: gocyclo
func (cfg *Config) validateAndApplyDefaults() error {
	if cfg.Watcher == nil {
		return errors.New("config: No Watcher block was present")
	}

	if cfg.Watcher.EthereumNodeAddress == "" {
		return errors.New("config: Ethereum node address was not specified")
	}

	if cfg.Watcher.NymContract == "" {
		return errors.New("config: The address of ERC20 Nym contract was not specified")
	}

	if cfg.Watcher.PipeAccount == "" {
		return errors.New("config: The address of the Pipe/Holding account was not specified")
	}

	if _, err := os.Stat(cfg.Watcher.KeyFile); err != nil {
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
