// main_sample.go - sample usage for coconut/tendermint client
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
	"os"
	"os/signal"
	"syscall"

	cclient "0xacab.org/jstuczyn/CoconutGo/client"
	"0xacab.org/jstuczyn/CoconutGo/client/config"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	tmclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const providerAddress = "127.0.0.1:4000"
const providerAddressGrpc = "127.0.0.1:5000"

var tendermintABCIAddresses = []string{
	"tcp://0.0.0.0:12345", // does not exist
	"tcp://0.0.0.0:46657",
	"tcp://0.0.0.0:46667",
	"tcp://0.0.0.0:46677",
	"tcp://0.0.0.0:46687",
}

// const tendermintABCIAddress = "tcp://0.0.0.0:26657"

func getRandomAttributes(G *bpgroup.BpGroup, n int) []*Curve.BIG {
	attrs := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		attrs[i] = Curve.Randomnum(G.Order(), G.Rng())
	}
	return attrs
}

// nolint: gosec, lll, errcheck
func main() {
	cfgFile := flag.String("f", "config.toml", "Path to the server config file.")
	flag.Parse()

	syscall.Umask(0077)

	haltCh := make(chan os.Signal)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			<-haltCh
			fmt.Println("Received SIGTERM...")
			os.Exit(0)
		}
	}()

	cfg, err := config.LoadFile(*cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Start up the coconut client.
	cc, err := cclient.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to spawn client instance: %v\n", err)
		os.Exit(-1)
	}

	// IAInteractions(cc)
	blockchainInteractions(cc)
}

func IAInteractions(cc *cclient.Client) {
	useGRPC := false

	params, _ := coconut.Setup(5)
	G := params.G
	pubM := getRandomAttributes(G, 3)
	privM := getRandomAttributes(G, 2)
	// all possible interactions with the IAs/SPs

	if useGRPC {
		sigGrpc, _ := cc.SignAttributesGrpc(pubM)
		sigBlindGrpc, _ := cc.BlindSignAttributesGrpc(pubM, privM)
		vkGrpc, _ := cc.GetAggregateVerificationKeyGrpc()

		isValidGrpc, _ := cc.SendCredentialsForVerificationGrpc(pubM, sigGrpc, providerAddressGrpc)
		isValidBlind1Grpc, _ := cc.SendCredentialsForBlindVerificationGrpc(pubM, privM, sigBlindGrpc, providerAddressGrpc, nil)
		isValidBlind2Grpc, _ := cc.SendCredentialsForBlindVerificationGrpc(pubM, privM, sigBlindGrpc, providerAddressGrpc, vkGrpc)
		isValidBlind3Grpc, _ := cc.SendCredentialsForVerificationGrpc(append(privM, pubM...), sigBlindGrpc, providerAddressGrpc)

		fmt.Println("Is validGrpc:", isValidGrpc)
		fmt.Println("Is valid localGrpc:", coconut.Verify(params, vkGrpc, pubM, sigGrpc))

		fmt.Println("Is validBlind1Grpc:", isValidBlind1Grpc)
		fmt.Println("Is validBlind2Grpc:", isValidBlind2Grpc)
		fmt.Println("Is validBlind3Grpc:", isValidBlind3Grpc)
	} else {
		sig, _ := cc.SignAttributes(pubM)
		sigBlind, _ := cc.BlindSignAttributes(pubM, privM)
		vk, _ := cc.GetAggregateVerificationKey()

		isValid, _ := cc.SendCredentialsForVerification(pubM, sig, providerAddress)
		isValidBlind1, _ := cc.SendCredentialsForBlindVerification(pubM, privM, sigBlind, providerAddress, nil)
		isValidBlind2, _ := cc.SendCredentialsForBlindVerification(pubM, privM, sigBlind, providerAddress, vk)
		isValidBlind3, _ := cc.SendCredentialsForVerification(append(privM, pubM...), sigBlind, providerAddress)

		fmt.Println("Is valid", isValid)
		fmt.Println("Is valid local:", coconut.Verify(params, vk, pubM, sig))

		fmt.Println("Is validBlind1:", isValidBlind1)
		fmt.Println("Is validBlind2:", isValidBlind2)
		fmt.Println("Is validBlind3:", isValidBlind3)
	}

}

func blockchainInteractions(cc *cclient.Client) {
	// decides whether we should wait for tx to be included in a block or just to pass CheckTx
	waitForCommit := true

	// create new account
	acc := account.NewAccount()
	newAccReq, err := transaction.CreateNewAccountRequest(acc, []byte("foo"))
	if err != nil {
		panic(err)
	}

	debugAcc := &account.Account{}
	debugAcc.FromJSONFile("../tendermint/debugAccount.json")

	// transfer some funds to the new account
	transferReq, err := transaction.CreateNewTransferRequest(*debugAcc, acc.PublicKey, 100)
	if err != nil {
		panic(err)
	}

	params, _ := coconut.Setup(5)
	G := params.G

	privM := getRandomAttributes(G, 2) // sequence and the key

	token := token.New(privM[0], privM[1], int32(10))

	// sign it as 'normal' set of public/private attributes for now, treat it as the credential
	// cred, err := cc.GetCredential(token)
	// fmt.Println(cred)
	// fmt.Println(err)
	sig, err := cc.BlindSignAttributes(token.GetPublicAndPrivateSlices())
	if err != nil {
		panic(err)
	}

	log, err := logger.New("", "DEBUG", false)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a logger: %v", err))
	}

	tmclient, err := tmclient.New(tendermintABCIAddresses, log)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a tmclient: %v", err))
	}

	if waitForCommit {
		// send the requests:
		// new acc
		res, err := tmclient.Broadcast(newAccReq)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Created new account. Code: %v, additional data: %v\n", code.ToString(res.DeliverTx.Code), string(res.DeliverTx.Data))
		// add some funds
		res, err = tmclient.Broadcast(transferReq)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Transferred funds from debug to new account. Code: %v, additional data: %v\n", code.ToString(res.DeliverTx.Code), string(res.DeliverTx.Data))

		_ = sig
		// err = cc.SpendCredential(token, sig, []byte("foo"))
		// if err != nil {
		// 	panic(err)
		// }
		// nonce := []byte("foobara")
		// holdingReq1, err := transaction.CreateNewTransferToHoldingRequest(acc, 42, nonce)
		// if err != nil {
		// 	panic(err)
		// }
		// res, err = tmclient.Broadcast(holdingReq1)
		// if err != nil {
		// 	panic(err)
		// }
		// fmt.Println(res)
		// fmt.Printf("Transfered to holding. Code: %v, data: %v\n", code.ToString(res.DeliverTx.Code), string(res.DeliverTx.Data))
		// holdingReq2, err := transaction.CreateNewTransferToHoldingRequest(acc, 10, nonce)
		// if err != nil {
		// 	panic(err)
		// }
		// res, err = tmclient.Broadcast(holdingReq2)
		// if err != nil {
		// 	panic(err)
		// }
		// fmt.Printf("Transfered to holding. Code: %v, data: %v\n", code.ToString(res.DeliverTx.Code), string(res.DeliverTx.Data))
		// fmt.Println(res)

		// should succeed

		// should fail (repeated nonce)

	} else {
		// send the requests:
		// new acc
		res, err := tmclient.SendSync(newAccReq)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Created new account. Code: %v, additional data: %v\n", code.ToString(res.Code), string(res.Data))
		// add some funds

		res, err = tmclient.SendSync(transferReq)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Transferred funds from debug to new account. Code: %v, additional data: %v\n", code.ToString(res.Code), string(res.Data))
	}

	// params, _ := coconut.Setup(5)

	// // generate token
	// value := int32(1000)
	// seq := Curve.Randomnum(params.P(), params.G.Rng())
	// privateKey := Curve.Randomnum(params.P(), params.G.Rng())

	// token := token.New(seq, privateKey, value)
	// pubM, privM := token.GetPublicAndPrivateSlices()

	// // get credential
	// sig, _ := cc.BlindSignAttributes(pubM, privM)

	// // get aggregate vk needed for show protocol
	// avk, _ := cc.GetAggregateVerificationKey()

	// // generate random merchant (abci is set to create new accounts for new merchants)
	// merchantAddrEC := Curve.G1mul(params.G1(), Curve.Randomnum(params.P(), params.G.Rng()))
	// merchantAddr := make([]byte, constants.ECPLen)
	// merchantAddrEC.ToBytes(merchantAddr, true)

	// reqT, err := transaction.CreateNewDepositCoconutCredentialRequest(params, avk, sig, token, merchantAddr)
	// if err != nil {
	// 	panic(err)
	// }

	// if waitForCommit {
	// 	res, err := tmclient.Broadcast(reqT)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Printf("Deposited Credential. Code: %v, additional data: %v\n", code.ToString(res.DeliverTx.Code), res.DeliverTx.Data)
	// } else {
	// 	res, err := tmclient.SendSync(reqT)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Printf("Deposited Credential. Code: %v, additional data: %v\n", code.ToString(res.Code), res.Data)
	// }

}
