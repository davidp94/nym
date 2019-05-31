// main_test.go - entry point for the tests for the nymapplication
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

package nymapplication

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/tendermint/tendermint/libs/log"
)

//nolint: gochecknoglobals
var app *NymApplication

func TestMain(m *testing.M) {
	tmpDbDir, err := ioutil.TempDir("", "auxiliaryTestDir")
	if err != nil {
		panic(err)
	}

	logger := log.NewTMLogger(log.NewSyncWriter(ioutil.Discard)).With("module", "test")

	app = NewNymApplication("leveldb", tmpDbDir, logger)
	runTests := m.Run()

	os.RemoveAll(tmpDbDir)
	os.Exit(runTests)
}
