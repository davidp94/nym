// main.go - Entry point for Tendermint ABCI for Nym
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
package main

import (
	"fmt"
	"os"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/nymapplication"
	"github.com/tendermint/tendermint/abci/server"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/log"
)

const (
	// TODO: just replace with "memdb" ?
	DBTYPE = "leveldb"
	dbPath = "/nymabci"
)

func main() {
	// no need to pass it as a flag anymore. the location can be redefined using docker volumes
	// dbPath := flag.String("dbpath", "", "defines path to db to store app state")

	// EnsureDir checks if given dir exists and if it doesnt, creates the entire path
	if err := cmn.EnsureDir(dbPath, 0700); err != nil {
		panic(fmt.Errorf("Could not create DB directory: %v", err.Error()))
	}

	// TODO: location of logger, etc
	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout)).With("module", "abci-server")
	app := nymapplication.NewNymApplication(DBTYPE, dbPath, logger.With("module", "nym-app"))

	srv, err := server.NewServer("tcp://0.0.0.0:26658", "socket", app)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	srv.SetLogger(logger)
	if err := srv.Start(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	cmn.TrapSignal(logger, func() {
		srv.Stop()
		logger.Info("Server was stopped")
	})

	select {}
}
