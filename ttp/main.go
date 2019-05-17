// main.go - Main file for a simple Trusted Third Party (TTP) keygen CLI
// Copyright (C) 2018-2019  Jedrzej Stuczynski.
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
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
)

// main takes the arguments passed on command line
// and generates set of Coconut threshold keys according with the following:
// attributes: maximum number of arguments the keys are capable of signing
// n: number of keys to generate
// t: threshold parameter
// f: directory to save the keys at
func main() {
	numAttrs := flag.Int("attributes", -1, "How many attributes should keys be able to sign")
	n := flag.Int("n", -1, "Number of keys to generate")
	t := flag.Int("t", -1, "Threshold of keys")
	folder := flag.String("f", "", "Folder to save the keys at")

	rand.Seed(time.Now().UnixNano())

	flag.Parse()

	params, err := coconut.Setup(*numAttrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate params: %v\n", err)
		os.Exit(-1)
	}

	sks, vks, err := coconut.TTPKeygen(params, *t, *n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate keys: %v\n", err)
		os.Exit(-1)
	}

	if *folder == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get cwd: %v\n", err)
			os.Exit(-1)
		}
		suffix := rand.Intn(10000)
		*folder = filepath.Join(cwd, fmt.Sprintf("keys%v", suffix))
	}

	if _, err := os.Stat(*folder); os.IsNotExist(err) {
		if err := os.Mkdir(*folder, 0760); err != nil {
			log.Fatal(err)
		}
	}

	for i := range sks {
		skPathName := filepath.Join(*folder, fmt.Sprintf("secret%v-n=%v-t=%v.pem", i, *n, *t))
		vkPathName := filepath.Join(*folder, fmt.Sprintf("verification%v-n=%v-t=%v.pem", i, *n, *t))

		if err := sks[i].ToPEMFile(skPathName); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save secret key: %v\n", err)
			os.Exit(-1)
		}
		if err := vks[i].ToPEMFile(vkPathName); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save verification key: %v\n", err)
			os.Exit(-1)
		}
	}

	fmt.Println("Generated and saved the threshold keys.")
}
