// provider.go - service provider daemon.
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

	"0xacab.org/jstuczyn/CoconutGo/daemon"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
	"0xacab.org/jstuczyn/CoconutGo/server/provider"
)

func main() {
	daemon.Start(func() {
		flag.String("f", "/config.toml", "Path to the config file of the provider")
	},
		func() daemon.Service {
			cfgFile := flag.Lookup("f").Value.(flag.Getter).Get().(string)
			cfg, err := config.LoadFile(cfgFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", cfgFile, err)
				os.Exit(-1)
			}

			// Start up the provider.
			provider, err := provider.New(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to spawn provider instance: %v\n", err)
				os.Exit(-1)
			}
			return provider
		})
}
