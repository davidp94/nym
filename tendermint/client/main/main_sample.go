// main_sample.go - sample usage for tendermint client
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

	cclient "0xacab.org/jstuczyn/CoconutGo/client"
	"0xacab.org/jstuczyn/CoconutGo/client/config"
	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	tmclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

func getRandomAttributes(G *bpgroup.BpGroup, n int) []*Curve.BIG {
	attrs := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		attrs[i] = Curve.Randomnum(G.Order(), G.Rng())
	}
	return attrs
}

// currently used entirely for debug purposes
func main() {
	cfg, err := config.LoadFile("config.toml")
	if err != nil {
		panic(err)
	}

	cclient, err := cclient.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to spawn client instance: %v\n", err)
		panic(err)
	}

	params, _ := coconut.Setup(5)

	value := int32(1000)
	seq := Curve.Randomnum(params.P(), params.G.Rng())
	privateKey := Curve.Randomnum(params.P(), params.G.Rng())

	token := token.New(seq, privateKey, value)
	pubM, privM := token.GetPublicAndPrivateSlices()

	sig, _ := cclient.BlindSignAttributes(pubM, privM)

	log, err := logger.New("", "DEBUG", false)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a logger: %v", err))
	}

	tmclient, err := tmclient.New("tcp://0.0.0.0:46667", log)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a tmclient: %v", err))
	}

	merchantAddrEC := Curve.G1mul(params.G1(), Curve.Randomnum(params.P(), params.G.Rng()))
	merchantAddr := make([]byte, constants.ECPLen)
	merchantAddrEC.ToBytes(merchantAddr, true)

	avk, _ := cclient.GetAggregateVerificationKey()

	reqT, err := transaction.CreateNewDepositCoconutCredentialRequest(params, avk, sig, token, merchantAddr)
	if err != nil {
		panic(err)
	}

	res, _ := tmclient.Broadcast(reqT)
	fmt.Println("verify", res.DeliverTx.Code, res.DeliverTx.Data)

	// debugAcc := &account.Account{}
	// if err := debugAcc.FromJSONFile("debugAccount.json"); err != nil {
	// 	panic(err)
	// }

	// testAcc := account.NewAccount()
	// credential := []byte("foo")

	// req, err := transaction.CreateNewAccountRequest(testAcc, credential)
	// if err != nil {
	// 	panic(err)
	// }

	// res, _ := client.Broadcast(req)
	// fmt.Println("create", res.DeliverTx.Code)

	// path := query.QueryCheckBalancePath
	// testAcc.PublicKey.Compress()

	// // should be start
	// resQ, _ := client.Query(path, []byte(debugAcc.PublicKey))
	// fmt.Println("pre1", resQ.Response.Code, binary.BigEndian.Uint64(resQ.Response.Value))

	// // should be 0
	// resQ, _ = client.Query(path, []byte(testAcc.PublicKey))
	// fmt.Println("pre2", resQ.Response.Code, binary.BigEndian.Uint64(resQ.Response.Value))

	// reqT, err := transaction.CreateNewTransferRequest(*debugAcc, testAcc.PublicKey, 9001)
	// if err != nil {
	// 	panic(err)
	// }

	// res, _ = client.Broadcast(reqT)
	// fmt.Println("transfer", res.DeliverTx.Code)

	// // should be start - 9001
	// resQ, _ = client.Query(path, []byte(debugAcc.PublicKey))
	// fmt.Println("post1", resQ.Response.Code, binary.BigEndian.Uint64(resQ.Response.Value))

	// // should be 9001
	// resQ, _ = client.Query(path, []byte(testAcc.PublicKey))
	// fmt.Println("post2", resQ.Response.Code, binary.BigEndian.Uint64(resQ.Response.Value))

	// client.Stop()
}

// func main() {
// 	// priv := ed25519.GenPrivKey()
// 	// pub := priv.PubKey()
// 	// fmt.Println(priv)
// 	// fmt.Println(priv.Bytes())
// 	// fmt.Println(pub)
// 	// fmt.Println(pub.Bytes())

// 	bpgroup := bpgroup.New()

// 	z1 := Curve.G1mul(bpgroup.Gen1(), Curve.Randomnum(bpgroup.Order(), bpgroup.Rng()))

// 	b1 := make([]byte, constants.ECPLen)
// 	b2 := make([]byte, constants.ECPLenUC)

// 	z1.ToBytes(b1, true)
// 	z1.ToBytes(b2, false)

// 	fmt.Println(b1)

// 	fmt.Println(b2)
// }
