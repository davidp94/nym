// main.go - Entrypoint to the custom Nym Tendermint node.
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
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/nymapplication"
	"github.com/spf13/viper"
	tmConfig "github.com/tendermint/tendermint/config"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/log"
	tmNode "github.com/tendermint/tendermint/node"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/proxy"
)

const (
	// TODO: just replace with "memdb" ?
	abciDbType = "leveldb"
	abciDbDir  = "nymabci"
)

// It is assumed the node will be run in a docker container or on a fresh machine
// hence all data could be stored on the main path.
// However, if it's not the case, the base directory can be overwritten - for example for testing.
// TODO: another config.toml file for that?; perhaps worry about it once tendermint-related code
// is moved to a separate repo
// alternatively since all those options are in the node config.toml file,
// first read it and then overwrite what we need?
func createConfig(cfgFile, nodeRootDir string, createEmptyBlocks bool, emptyBlocksInterval time.Duration,
) (*tmConfig.Config, error) {
	// use the saved config.toml as the starting point
	// can't use tmConfig.DefaultConfig() as the saved one contains addresses of other nodes (if applicable)
	cfg := tmConfig.DefaultConfig()

	// we need to use viper for decoding the file due tendermint using it
	viper.SetConfigFile(cfgFile)
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	fmt.Println("Using config file:", viper.ConfigFileUsed())

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// we want to be able to store data outside the default path for testing, etc.
	if nodeRootDir != "" {
		cfg.SetRoot(nodeRootDir)
	}

	cfg.Consensus.CreateEmptyBlocks = createEmptyBlocks
	cfg.Consensus.CreateEmptyBlocksInterval = emptyBlocksInterval

	if !cmn.FileExists(cfg.GenesisFile()) ||
		!cmn.FileExists(cfg.NodeKeyFile()) ||
		!cmn.FileExists(cfg.PrivValidatorKeyFile()) ||
		!cmn.FileExists(cfg.PrivValidatorStateFile()) {
		return nil, errors.New("Node was not initialised - relevant files do not exist.")
	}

	cfg.LogLevel = "foo"

	if err := cfg.ValidateBasic(); err != nil {
		panic(err)
	}

	return cfg, nil
}

func appClientCreator(dbType, dbDir string, logger log.Logger) proxy.ClientCreator {
	return proxy.NewLocalClientCreator(nymapplication.NewNymApplication(dbType, dbDir, logger))
}

func createBaseLoger(writer ...io.Writer) log.Logger {
	if len(writer) != 1 {
		return log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	}
	return log.NewTMLogger(writer[0])
}

func createNymNode(cfgFile, dataRoot string, createEmptyBlocks bool, emptyBlocksInterval time.Duration,
) (*tmNode.Node, error) {
	log := createBaseLoger()
	log.Info("Initialised logger")

	cfg, err := createConfig(cfgFile, dataRoot, false, 0)
	if err != nil {
		return nil, err
	}
	log.Info("Initialised node config", cfg)

	nodeKey, err := p2p.LoadOrGenNodeKey(cfg.NodeKeyFile())
	if err != nil {
		// should have been detected when loading config, so it's undefined behaviour
		return nil, err
	}

	node, err := tmNode.NewNode(cfg,
		privval.LoadOrGenFilePV(cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile()),
		nodeKey,
		appClientCreator(abciDbType, filepath.Join(dataRoot, abciDbDir), log.With("module", "nym-app")),
		tmNode.DefaultGenesisDocProviderFunc(cfg),
		tmNode.DefaultDBProvider,
		tmNode.DefaultMetricsProvider(cfg.Instrumentation),
		log,
	)

	if err != nil {
		log.Error("Failed to create node: %+v\n", err)
		return nil, err
	}

	return node, nil
}

func main() {
	cfgFile := "/home/jedrzej/.tendermint/config/config.toml"
	dataRoot := "/home/jedrzej/.tendermint"

	node, err := createNymNode(cfgFile, dataRoot, false, 0)
	if err != nil {
		panic(err)
	}

	if err = node.Start(); err != nil {
		fmt.Printf("Failed to start node: %+v\n", err)
		panic(err)
	}

	// Trap signal, run forever.
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	node.Stop()
	fmt.Println("Node was stopped")
}
