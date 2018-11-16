// config.go - config for coconut client
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

// Package config defines configuration used by coconut client.
package config

// todo: once all options are figured out, introduce validation

import (
	"errors"
	"io/ioutil"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const (
	defaultLogLevel = "NOTICE"

	defaultConnectTimeout = 2 * 1000 // 1 sec.
	defaultRequestTimeout = 5 * 1000 // 5 sec.
	defaultMaxRequests    = 3
)

// nolint: gochecknoglobals
var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Client is the Coconut Client configuration.
type Client struct {
	// Identifier is the human readable identifier for the instance.
	Identifier string

	// IAAddresses are the IP address:port combinations of Issuing Authority Servers.
	IAAddresses []string

	// IAIDs are IDs of the servers used during generation of threshold keys.
	// If empty, it is going to be assumed that IAAddresses are ordered correctly.
	IAIDs []int

	// MaxRequests defines maximum number of concurrent requests each client can make.
	// -1 indicates no limit
	MaxRequests int

	// PersistentKeys specifies whether to use the keys from the files or create new ones every time.
	PersistentKeys bool

	// PublicKeyFile specifies the file containing the Coconut-specific ElGamal Public Key.
	PublicKeyFile string

	// PrivateKeyFile specifies the file containing the Coconut-specific ElGamal Private Key.
	PrivateKeyFile string

	// Threshold defines minimum number of signatures client needs to obtain. Default = len(IAAddresses).
	// 0 = no threshold
	Threshold int

	// MaximumAttributes specifies the maximum number of attributes the client will want to have signed.
	MaximumAttributes int
}

// Debug is the Coconut Client debug configuration.
type Debug struct {
	// ConnectTimeout specifies the maximum time a connection can take to establish a TCP/IP connection in milliseconds.
	ConnectTimeout int

	// RequestTimeout specifies the maximum time a client is going to wait for its request to resolve.
	RequestTimeout int

	// RegenerateKeys specifies whether to generate new Coconut-specific ElGamal keypair and overwrite existing files.
	RegenerateKeys bool
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.ConnectTimeout <= 0 {
		dCfg.ConnectTimeout = defaultConnectTimeout
	}
	if dCfg.RequestTimeout <= 0 {
		dCfg.RequestTimeout = defaultRequestTimeout
	}
}

// Logging is the Coconut Client logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

// Config is the top level Coconut Client configuration.
type Config struct {
	Client  *Client
	Logging *Logging

	Debug *Debug
}

func (cfg *Config) validateAndApplyDefaults() error {
	if cfg.Client == nil {
		return errors.New("config: No Client block was present")
	}
	// does not care if files are empty, if so, new keys will be generated and written there
	if cfg.Client.PersistentKeys && (cfg.Client.PrivateKeyFile == "" || cfg.Client.PublicKeyFile == "") {
		return errors.New("config: No key files were provided")
	}

	if cfg.Client.MaxRequests == 0 {
		cfg.Client.MaxRequests = defaultMaxRequests
	}

	if len(cfg.Client.IAIDs) <= 0 {
		IAIDs := make([]int, len(cfg.Client.IAAddresses))
		for i := range cfg.Client.IAAddresses {
			IAIDs[i] = i + 1
		}
	} else if len(cfg.Client.IAIDs) != len(cfg.Client.IAAddresses) {
		return errors.New("config: Invalid server configuration")
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
