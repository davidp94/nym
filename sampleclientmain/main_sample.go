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
	"crypto/ecdsa"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	cclient "0xacab.org/jstuczyn/CoconutGo/client"
	"0xacab.org/jstuczyn/CoconutGo/client/config"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	tmclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/query"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const onlyRunBasic = false
const providerAddress = "127.0.0.1:4000"
const providerAddressGrpc = "127.0.0.1:5000"
const providerAcc = "AwYXtM4pa4WV47TozIi1gf6t/jdRQyQkPv6mAC0S/fyzdPP4Pr3DAtOP0h0BYcHQIQ=="

//nolint: gochecknoglobals
var tendermintABCIAddresses = []string{
	// "tcp://0.0.0.0:12345", // does not exist
	"tcp://0.0.0.0:26657",
	"tcp://0.0.0.0:26659",
	"tcp://0.0.0.0:26661",
	"tcp://0.0.0.0:26663",
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
	cfgFile := flag.String("f", "config.toml", "Path to the client config file.")
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

	nymFlow(cc)
	return

	// TODO: FIXME:
	if onlyRunBasic {
		basicIA(cc)
	} else {
		wholeSystem(cc)
	}
}

func nymFlow(cc *cclient.Client) {
	params, err := coconut.Setup(1)
	if err != nil {
		panic(err)
	}
	s := Curve.Randomnum(params.P(), params.G.Rng())
	k := Curve.Randomnum(params.P(), params.G.Rng())
	token, err := token.New(s, k, 1)
	if err != nil {
		panic(err)
	}
	cc.GetCredential(token)

	// currentERC20Balance, err := cc.GetCurrentERC20Balance()
	// if err != nil {
	// 	panic(err)
	// }
	// pending, err := cc.GetCurrentERC20PendingBalance()
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("current erc20 balance:", currentERC20Balance, "pending:", pending)

	// currentNymBalance, err := cc.GetCurrentNymBalance()
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("current nym balance:", currentNymBalance)

	// if err := cc.SendToPipeAccountWrapper(1); err != nil {
	// 	panic(err)
	// }

	// pending2, err := cc.GetCurrentERC20PendingBalance()
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Current pending", pending2)

}

//nolint: errcheck
func wholeSystem(cc *cclient.Client) {
	currentBalance, err := cc.GetCurrentNymBalance()
	if err != nil {
		panic(err)
	}

	fmt.Println("current balance:", currentBalance)

	return

	log, err := logger.New("", "DEBUG", false)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a logger: %v", err))
	}

	tmclient, err := tmclient.New(tendermintABCIAddresses, log)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a tmclient: %v", err))
	}

	// create new account
	pk, err := ethcrypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	newAccReq, err := transaction.CreateNewAccountRequest(pk, []byte("foo"))
	if err != nil {
		panic(err)
	}

	res, err := tmclient.Broadcast(newAccReq)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created new account. Code: %v, additional data: %v\n",
		code.ToString(res.DeliverTx.Code),
		string(res.DeliverTx.Data),
	)

	debugAcc, lerr := ethcrypto.LoadECDSA("../tendermint/debugAccount.key")
	if lerr != nil {
		panic(lerr)
	}

	newAccAddress := ethcrypto.PubkeyToAddress(*pk.Public().(*ecdsa.PublicKey))
	debugAccAddress := ethcrypto.PubkeyToAddress(*debugAcc.Public().(*ecdsa.PublicKey))

	queryRes, err := tmclient.Query(query.QueryCheckBalancePath, debugAccAddress[:])
	if err != nil {
		panic(err)
	}

	fmt.Println("Debug Account Balance: ", binary.BigEndian.Uint64(queryRes.Response.Value))

	// transfer some funds to the new account
	transferReq, err := transaction.CreateNewTransferRequest(debugAcc, newAccAddress, 42)
	if err != nil {
		panic(err)
	}

	// params, _ := coconut.Setup(5)
	// G := params.G
	// privM := getRandomAttributes(G, 2) // sequence and the key
	// token := token.New(privM[0], privM[1], int32(1))
	// _ = token

	// add some funds
	res, err = tmclient.Broadcast(transferReq)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Transferred funds from debug to new account. Code: %v, additional data: %v\n",
		code.ToString(res.DeliverTx.Code),
		string(res.DeliverTx.Data),
	)

	queryRes, err = tmclient.Query(query.QueryCheckBalancePath, debugAccAddress[:])
	if err != nil {
		panic(err)
	}

	fmt.Println("Debug Account Balance after transfer: ", binary.BigEndian.Uint64(queryRes.Response.Value))

	// b, err := utils.GenerateRandomBytes(10)
	// if err != nil {
	// 	panic(err)
	// }
	// tmclient.SendAsync(append([]byte{transaction.TxAdvanceBlock, 0x01}, b...))
	// tmclient.SendAsync(append([]byte{transaction.TxAdvanceBlock, 0x02}, b...))
	// tmclient.SendAsync(append([]byte{transaction.TxAdvanceBlock, 0x03}, b...))
	// tmclient.SendAsync(append([]byte{transaction.TxAdvanceBlock, 0x04}, b...))
	// tmclient.SendAsync(append([]byte{transaction.TxAdvanceBlock, 0x05}, b...))

	// fmt.Printf("Send some dummy transactions to advance block")

	// cred, err := cc.GetCredential(token)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("Transferred %v to the pipe account\n", token.Value())
	// fmt.Printf("Obtained Credential: %v %v\n", cred.Sig1().ToString(), cred.Sig2().ToString())

	// addr, err := base64.StdEncoding.DecodeString(providerAcc)
	// if err != nil {
	// 	panic(err)
	// }
	// // spend credential:
	// didSucceed, err := cc.SpendCredential(token, cred, providerAddress, addr, nil)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Was credential spent: ", didSucceed)
}

//nolint: dupl, lll
func basicIA(cc *cclient.Client) {
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
