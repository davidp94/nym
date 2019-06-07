// nymnode.go - nymnode daemon.
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
	"flag"
	"fmt"
	"os"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/daemon"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymnode"
)

func main() {
	daemon.Start(func() {
		flag.String("cfgFile", "/tendermint/config/config.toml", "The main tendermint configuration file")
		flag.String("dataRoot", "/tendermint", "The data root directory")
		flag.Bool("createEmptyBlocks",
			false,
			"Flag to indicate whether tendermint should create empty blocks",
		)
		flag.Duration("emptyBlocksInterval",
			0,
			"(if applicable) used to indicate interval between empty blocks",
		)
	},
		func() daemon.Service {
			cfgFile := flag.Lookup("cfgFile").Value.(flag.Getter).Get().(string)
			dataRoot := flag.Lookup("dataRoot").Value.(flag.Getter).Get().(string)
			createEmptyBlocks := flag.Lookup("createEmptyBlocks").Value.(flag.Getter).Get().(bool)
			emptyBlocksInterval := flag.Lookup("emptyBlocksInterval").Value.(flag.Getter).Get().(time.Duration)

			node, err := nymnode.CreateNymNode(cfgFile, dataRoot, createEmptyBlocks, emptyBlocksInterval)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create NymNode: %v\n", err)
				os.Exit(-1)
			}
			return node
		})
}
