// config_test.go - server configuration tests
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
	"fmt"
	"strings"
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/server/config"
	"github.com/stretchr/testify/assert"
)

func makeStringOfAddresses(name string, addrs []string) string {
	out := name + " = ["
	for i, addr := range addrs {
		out += fmt.Sprintf("\"%v\"", addr)
		if i != len(addrs)-1 {
			out += ","
		}
	}
	out += "]\n"
	return out
}

func TestServer(t *testing.T) {
	invalidCfgs := []string{
		`
		[Server]
		IsIssuer = true
		Addresses = []
		[Issuer]
		SecretKeyFile = "/foo/bar"
		VerificationKeyFile = "/foo/bar"
		`,
		`
		[Server]
		MaximumAttributes = 4000
		IsIssuer = true
		Addresses = []
		[Issuer]
		SecretKeyFile = "/foo/bar"
		VerificationKeyFile = "/foo/bar"
		`,
		`
		[Server]
		MaximumAttributes = 5
		IsIssuer = true
		Addresses = []
		[Issuer]
		SecretKeyFile = "/foo/bar"
		VerificationKeyFile = "/foo/bar"
		`,
		`
		[Server]
		MaximumAttributes = 5
		IsIssuer = true
		GRPCAddresses = []
		[Issuer]
		SecretKeyFile = "/foo/bar"
		VerificationKeyFile = "/foo/bar"
		`,
		`
		[Server]
		MaximumAttributes = 5
		IsIssuer = true
		Addresses = []
		GRPCAddresses = []
		[Issuer]
		SecretKeyFile = "/foo/bar"
		VerificationKeyFile = "/foo/bar"
		`,
	}

	for _, invalidCfg := range invalidCfgs {
		cfg, err := config.LoadBinary([]byte(invalidCfg))
		assert.Nil(t, cfg)
		assert.Error(t, err)
	}

	tcpAddresses := []int{0, 1, 3}
	grpcAddresses := []int{0, 1, 3}

	for _, tcpaddrnum := range tcpAddresses {
		for _, grpcaddrnum := range grpcAddresses {
			tcpaddrs := make([]string, tcpaddrnum)
			grpcaddrs := make([]string, grpcaddrnum)
			for i := 0; i < tcpaddrnum; i++ {
				tcpaddrs[i] = fmt.Sprintf("127.0.0.1:100%v", i)
			}
			for i := 0; i < grpcaddrnum; i++ {
				grpcaddrs[i] = fmt.Sprintf("127.0.0.1:200%v", i)
			}

			cfgstr := strings.Join([]string{string(`
			[Server]
			MaximumAttributes = 5
			IsIssuer = true
			`),
				makeStringOfAddresses("Addresses", tcpaddrs),
				makeStringOfAddresses("GRPCAddresses", grpcaddrs),
				string(`
			[Issuer]
			SecretKeyFile = "/foo/bar"
			VerificationKeyFile = "/foo/bar"
			`)}, "")

			cfg, err := config.LoadBinary([]byte(cfgstr))
			if tcpaddrnum == 0 && grpcaddrnum == 0 {
				assert.Nil(t, cfg)
				assert.Error(t, err)
			} else {
				assert.NotNil(t, cfg)
				assert.Nil(t, err)
			}
		}
	}
}

func TestIssuer(t *testing.T) {
	// shouldn't care about block present when flag is not set
	_, err := config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsIssuer = false
	Addresses = [ "127.0.0.1:4000" ]
	[Issuer]
	SecretKeyFile = "/foo/bar"
	VerificationKeyFile = "/foo/bar"
	`))
	assert.Error(t, err)

	// empty block
	_, err = config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsIssuer = true
	Addresses = [ "127.0.0.1:4000" ]
	`))
	assert.Error(t, err)

	// needs both keys to be explicitly set
	_, err = config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsIssuer = true
	Addresses = [ "127.0.0.1:4000" ]
	GRPCAddresses = []
	[Issuer]
	SecretKeyFile = "/foo/bar"
	`))
	assert.Error(t, err)

	_, err = config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsIssuer = true
	Addresses = [ "127.0.0.1:4000" ]
	GRPCAddresses = []
	[Issuer]
	VerificationKeyFile = "/foo/bar"
	`))
	assert.Error(t, err)
}

func TestProvider(t *testing.T) {
	// shouldn't care about block present when flag is not set
	_, err := config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsProvider = false
	Addresses = [ "127.0.0.1:4000" ]
	[Provider]
	SecretKeyFile = "/foo/bar"
	VerificationKeyFile = "/foo/bar"
	`))
	assert.Error(t, err)

	// empty block
	_, err = config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsProvider = true
	Addresses = [ "127.0.0.1:4000" ]
	`))
	assert.Error(t, err)

	cfg, err := config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsProvider = true
	Addresses = [ "127.0.0.1:4000" ]
	[Provider]
	IAAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
	IAIDs = [ 19, 22, 332 ]
	`))
	assert.Nil(t, err)

	assert.Len(t, cfg.Provider.IAAddresses, 3)
	assert.Len(t, cfg.Provider.IAIDs, 3)

	assert.Equal(t, cfg.Provider.IAIDs[0], 19)
	assert.Equal(t, cfg.Provider.IAIDs[1], 22)
	assert.Equal(t, cfg.Provider.IAIDs[2], 332)

	cfg, err = config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsProvider = true
	Addresses = [ "127.0.0.1:4000" ]
	[Provider]
	IAAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
	IAIDs = [ 19, 22 ]
	`))
	assert.Nil(t, cfg)
	assert.Error(t, err)

	cfg, err = config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsProvider = true
	Addresses = [ "127.0.0.1:4000" ]
	[Provider]
	IAAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001" ]
	IAIDs = [ 19, 22, 332 ]
	`))
	assert.Nil(t, cfg)
	assert.Error(t, err)

	cfg, err = config.LoadBinary([]byte(`
	[Server]
	MaximumAttributes = 5
	IsProvider = true
	Addresses = [ "127.0.0.1:4000" ]
	[Provider]
	IAAddresses = [ "127.0.0.1:5000", "127.0.0.1:5001", "127.0.0.1:5002" ]
	`))
	assert.Nil(t, err)
	assert.Len(t, cfg.Provider.IAAddresses, len(cfg.Provider.IAIDs))

	for i := range cfg.Provider.IAAddresses {
		assert.Equal(t, cfg.Provider.IAIDs[i], i+1)
	}
}
