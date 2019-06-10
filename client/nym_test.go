// nym_test.go - tests for coconut nym-specific client API
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

// This package only cares about client handling of requests,
// tests for servers, services, etc will be in separate files.
// It is assumed that servers work correctly.
package client

import (
	"testing"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/stretchr/testify/assert"
)

var (
	// A temp. solution so that import would be used.s
	_ = Curve.AESKEY
)

func TestParseCredentialPairResponse(t *testing.T) {
	validStatus := &commands.Status{
		Code:    int32(commands.StatusCode_OK),
		Message: "",
	}

	// for this test, we don't need any client properties
	// only logger to not crash by trying to call object that doesn't exist
	log, err := logger.New("", "DEBUG", true)
	assert.Nil(t, err)
	emptyClient := &Client{log: log.GetLogger("Client")}

	sig, id, err := emptyClient.parseCredentialPairResponse(nil, nil)
	assert.Nil(t, sig)
	assert.True(t, id == -1)
	assert.Error(t, err)

	_ = validStatus
}
