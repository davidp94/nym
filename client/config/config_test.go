// config_test.go - client configuration tests
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

package config_test

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/client/config"
	"github.com/stretchr/testify/assert"
)

func TestEmpty(t *testing.T) {
	_, err := config.LoadBinary([]byte(""))
	assert.Error(t, err)

	_, err = config.LoadBinary([]byte(`
	[Client]
	IAAddresses = []
[Nym]
	AccountKeysFile = "foo.json"
	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
	`))
	assert.Error(t, err)

	_, err = config.LoadBinary([]byte(`
	[Client]
	UseGRPC = true
	IAgRPCAddresses = []
[Nym]
	AccountKeysFile = "foo.json"
	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
	`))
	assert.Error(t, err)
}

// //nolint: dupl
// func TestGRPCIDs(t *testing.T) {
// 	cfgStr := `[Client]
// 	UseGRPC = true
// 	IAgRPCAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
// 	IAIDs = [ 19, 22, 332 ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	cfg, err := config.LoadBinary([]byte(cfgStr))
// 	assert.Nil(t, err)

// 	assert.Len(t, cfg.Client.IAgRPCAddresses, 3)
// 	assert.Len(t, cfg.Client.IAIDs, 3)

// 	assert.Equal(t, cfg.Client.IAIDs[0], 19)
// 	assert.Equal(t, cfg.Client.IAIDs[1], 22)
// 	assert.Equal(t, cfg.Client.IAIDs[2], 332)

// 	cfgStr = `[Client]
// 	UseGRPC = false
// 	IAgRPCAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
// 	IAIDs = [ 19, 22, 332 ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	_, err = config.LoadBinary([]byte(cfgStr))
// 	assert.Error(t, err)

// 	cfgStr = `[Client]
// 	UseGRPC = true
// 	IAgRPCAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
// 	IAIDs = [ 19, 22 ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	_, err = config.LoadBinary([]byte(cfgStr))
// 	assert.Error(t, err)

// 	cfgStr = `[Client]
// 	UseGRPC = true
// 	IAgRPCAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001" ]
// 	IAIDs = [ 19, 22, 332 ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	_, err = config.LoadBinary([]byte(cfgStr))
// 	assert.Error(t, err)

// 	cfgStr = `[Client]
// 	UseGRPC = true
// 	IAgRPCAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
// 	IAIDs = [ ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	cfg, err = config.LoadBinary([]byte(cfgStr))
// 	assert.Nil(t, err)

// 	assert.Len(t, cfg.Client.IAgRPCAddresses, len(cfg.Client.IAIDs))

// 	for i := range cfg.Client.IAgRPCAddresses {
// 		assert.Equal(t, cfg.Client.IAIDs[i], i+1)
// 	}
// }

// //nolint: dupl
// func TestTCPIDs(t *testing.T) {
// 	cfgStr := `[Client]
// 	UseGRPC = false
// 	IAAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
// 	IAIDs = [ 19, 22, 332 ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	cfg, err := config.LoadBinary([]byte(cfgStr))
// 	assert.Nil(t, err)

// 	assert.Len(t, cfg.Client.IAAddresses, 3)
// 	assert.Len(t, cfg.Client.IAIDs, 3)

// 	assert.Equal(t, cfg.Client.IAIDs[0], 19)
// 	assert.Equal(t, cfg.Client.IAIDs[1], 22)
// 	assert.Equal(t, cfg.Client.IAIDs[2], 332)

// 	cfgStr = `[Client]
// 	UseGRPC = false
// 	IAgRPCAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
// 	IAIDs = [ 19, 22, 332 ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	_, err = config.LoadBinary([]byte(cfgStr))
// 	assert.Error(t, err)

// 	cfgStr = `[Client]
// 	UseGRPC = false
// 	IAAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
// 	IAIDs = [ 19, 22 ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	_, err = config.LoadBinary([]byte(cfgStr))
// 	assert.Error(t, err)

// 	cfgStr = `[Client]
// 	UseGRPC = false
// 	IAAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001" ]
// 	IAIDs = [ 19, 22, 332 ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	_, err = config.LoadBinary([]byte(cfgStr))
// 	assert.Error(t, err)

// 	cfgStr = `[Client]
// 	UseGRPC = false
// 	IAAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
// 	IAIDs = [ ]
// [Nym]
// 	AccountKeysFile = "foo.json"
// 	BlockchainNodeAddresses = [ "127.0.0.1:46667" ]
// 	`
// 	cfg, err = config.LoadBinary([]byte(cfgStr))
// 	assert.Nil(t, err)

// 	assert.Len(t, cfg.Client.IAAddresses, len(cfg.Client.IAIDs))

// 	for i := range cfg.Client.IAAddresses {
// 		assert.Equal(t, cfg.Client.IAIDs[i], i+1)
// 	}
// }

// TODO: test nym block behaviour
