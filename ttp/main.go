package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
)

// just generate n keys with threshold of t
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
		os.Mkdir(*folder, 0760)
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
