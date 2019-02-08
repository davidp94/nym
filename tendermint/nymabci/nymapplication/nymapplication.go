// nymapplication.go - Tendermint ABCI for Nym
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

// Package nymapplication defines the functionality of the blockchain application.
// The methods here are executed on each node. It is crucial that each result is entirely deterministic,
// otherwise it will break the consensus and the entire network will come to the halt.
package nymapplication

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/query"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/version"
)

// TODO: possible speed-up down the line: store all ECP in uncompressed form - it will take less time to recover them
// TODO: cleanup the file with old code used to get hang of tendermint

const (
	DBNAME                              = "nymDB"
	zl                                  = constants.ECPLen
	createAccountOnDepositIfDoesntExist = true
	holdingStartingBalance              = 100000 // entirely for debug purposes
)

var (
	// todo: move vars to appropriate files
	stateKey = []byte("stateKey")
	// zetaPrefix            = []byte("zeta")
	accountsPrefix        = []byte("account")
	holdingAccountAddress = []byte("HOLDING ACCOUNT")
	aggregateVkKey        = []byte("avk")
	coconutHs             = []byte("coconutHs")

	// TODO: will need to store all vks

	// entirely for debug purposes
	invalidPrefix = byte('a')

	ProtocolVersion version.Protocol = 0x1
)

// todo: validator updates etc

var _ types.Application = (*NymApplication)(nil)

// type State struct {
// 	db      dbm.DB
// 	Size    int64  `json:"size"`
// 	Height  int64  `json:"height"`
// 	AppHash []byte `json:"app_hash"`
// }

// TODO: is this an efficient solution? after all it doesnt return pointer to array since its not a slice and hence
// copies everything by value
// func prefixZeta(zeta [zl]byte) [zl + 4]byte {
// 	// TODO: surely there must be a better syntax for that
// 	arr := [zl + 4]byte{zetaPrefix[0], zetaPrefix[1], zetaPrefix[2], zetaPrefix[3]}
// 	copy(arr[4:], zeta[:])

// 	return arr
// }

func prefixKey(prefix []byte, key []byte) []byte {
	b := make([]byte, len(key)+len(prefix))
	copy(b, prefix)
	copy(b[len(prefix):], key)

	return b
}

type GenesisAppState struct {
	Accounts          []account.GenesisAccount `json:"accounts"`
	CoconutProperties struct {
		MaxAttrs           int `json:"q"`
		Threshold          int `json:"threshold`
		IssuingAuthorities []struct {
			Id int    `json:"id"`
			Vk []byte `json:"vk"`
		} `json:"issuingAuthorities"`
	} `json:"coconutProperties"`
}

type State struct {
	db *iavl.MutableTree // hash and height (version) are obtained from the tree methods
}

type NymApplication struct {
	types.BaseApplication
	state State

	// data cache for current block
	// zetaCache map[[zl + 4]byte][]byte // unlike slices, arrays can be used as keys in maps
	// todo: rethink the entire idea of caches, or remove them completely for now if it's not neccessary to keep
	// intermediate state for now.

	log log.Logger

	Version      string
	AppVersion   uint64
	CurrentBlock int64 // any point in this at this point?
}

func NewNymApplication(dbType, dbDir string, logger log.Logger) *NymApplication {
	fmt.Println("new")

	db := dbm.NewDB(DBNAME, dbm.DBBackendType(dbType), dbDir)
	tree := iavl.NewMutableTree(db, 0)
	_, err := tree.Load()
	if err != nil {
		// there's nothing we can do and application hasn't finished startup anyway,
		// so panic might be the most appropriate choice
		panic(err)
	}

	state := State{
		db: tree,
	}

	return &NymApplication{
		state:      state,
		log:        logger,
		Version:    version.ABCIVersion,
		AppVersion: ProtocolVersion.Uint64(),
	}
}

func (app *NymApplication) Info(req types.RequestInfo) types.ResponseInfo {
	fmt.Println("Info; height: ", app.state.db.Version())

	res := types.ResponseInfo{
		Data:             fmt.Sprintf("testmsg"),
		Version:          app.Version,
		AppVersion:       app.AppVersion,
		LastBlockHeight:  app.state.db.Version(),
		LastBlockAppHash: app.state.db.Hash(),
	}

	app.CurrentBlock = app.state.db.Version() // todo: needed?

	return res
}

func (app *NymApplication) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	fmt.Println("SetOption; height: ", app.state.db.Version(), req)

	return types.ResponseSetOption{}
}

// todo: move to transaction package and pass db as argument
func (app *NymApplication) lookUpZeta(zeta []byte) []byte {
	_, val := app.state.db.Get(zeta)

	if len(val) > 0 {
		return transaction.TruthBytes
	}
	return transaction.FalseBytes
}

// TODO: make sure to handle situation where in the same block there are both txs to lookup and spend given credential
func (app *NymApplication) DeliverTx(tx []byte) types.ResponseDeliverTx {
	fmt.Println("DeliverTx; height: ", app.state.db.Version())

	txType := tx[0]
	switch txType {
	case transaction.TxTypeLookUpZeta:
		app.log.Info("DeliverTx for lookup zeta")
		app.log.Info(fmt.Sprintf("looking up %v", tx[1:]))
		present := app.lookUpZeta(tx[1:])
		return types.ResponseDeliverTx{Code: code.OK, Data: present}

	case transaction.TxNewAccount:
		app.log.Info("New Account tx")
		return app.createNewAccount(tx[1:])
	case transaction.TxTransferBetweenAccounts:
		app.log.Info("Transfer tx")
		return app.transferFunds(tx[1:])
	case transaction.TxVerifyCredential:
		app.log.Info("Verify credential tx")
		return app.verifyCoconutCredential(tx[1:])
	case transaction.TxDepositCoconutCredential:
		app.log.Info("Deposit Credential")
		return app.depositCoconutCredential(tx[1:])

	case invalidPrefix:
		app.log.Info("Test Invalid Deliver")
		return types.ResponseDeliverTx{Code: code.UNKNOWN}

		// purely for debug purposes to populate the state and advance the blocks
	default:
		app.log.Info("default tx")
		app.log.Info(fmt.Sprintf("storing up %v", tx))

		app.state.db.Set(tx, []byte{1})
	}

	return types.ResponseDeliverTx{Code: code.OK, Data: tx}
}

func (app *NymApplication) validateTxLength(tx []byte) uint32 {
	txType := tx[0]
	switch txType {
	case transaction.TxTypeLookUpZeta:
		if len(tx) == constants.ECPLen+1 {
			return code.OK
		}
		return code.INVALID_TX_LENGTH
	default:
		// we can't compare the tx length with the expected one - we don't know what the correct one is supposed to be
		// TODO: contradicts the rule of failsafe defaults?
		return code.OK
	}
}

func (app *NymApplication) validateTx(tx []byte) uint32 {
	// TODO: more validations
	return app.validateTxLength(tx)
}

func (app *NymApplication) CheckTx(tx []byte) types.ResponseCheckTx {
	txType := tx[0]
	switch txType {
	case transaction.TxTypeLookUpZeta:
		app.log.Debug("CheckTx for lookup zeta")
	case transaction.TxNewAccount:
		app.log.Debug("CheckTx for TxNewAccount")
	case transaction.TxVerifyCredential:
		app.log.Debug("CheckTx for TxVerifyCredential")

	default:
		app.log.Debug("default CheckTx")
	}

	checkCode := app.validateTx(tx)
	if checkCode != code.OK {
		app.log.Info("Tx failed CheckTx")
	}

	fmt.Println("CheckTx; height: ", app.state.db.Version())

	return types.ResponseCheckTx{Code: checkCode}
}

func (app *NymApplication) Commit() types.ResponseCommit {
	fmt.Println("Commit; height: ", app.state.db.Version())
	app.state.db.SaveVersion()
	// app.zetaCache = make(map[[zl + 4]byte][]byte)
	return types.ResponseCommit{Data: app.state.db.Hash()}
	// return types.ResponseCommit{}
}

func (app *NymApplication) Query(req types.RequestQuery) types.ResponseQuery {
	switch req.Path {
	case query.QueryCheckBalancePath:
		val, code := app.queryBalance(req.Data)
		// TODO: include index (as found in the db)?
		return types.ResponseQuery{Code: code, Key: req.Data, Value: val}
	case query.DEBUG_printVk:
		_, avkb := app.state.db.Get(aggregateVkKey)
		avk := &coconut.VerificationKey{}
		err := avk.UnmarshalBinary(avkb)
		if err != nil {
			app.log.Error("Couldnt unmarshal avk")
			return types.ResponseQuery{Code: code.UNKNOWN}
		}
		fmt.Println(avk)
		return types.ResponseQuery{Code: code.OK}
	default:
		app.log.Info(fmt.Sprintf("Unknown Query Path: %v", req.Path))
	}
	fmt.Println("Query")

	// This information can be a simple query rather than tx because there's no risk in delivering possibly stale result
	fmt.Println(req.Path)
	fmt.Println(req.Data)

	return types.ResponseQuery{Code: code.OK}
}

func (app *NymApplication) InitChain(req types.RequestInitChain) types.ResponseInitChain {
	genesisState := &GenesisAppState{}
	if err := json.Unmarshal(req.AppStateBytes, genesisState); err != nil {
		app.log.Error("Failed to unmarshal genesis app state")
		panic(err)
	}
	app.log.Info(fmt.Sprintf("Adding %v genesis accounts", len(genesisState.Accounts)))

	for _, acc := range genesisState.Accounts {
		// always store account pubkey in compressed form, but accept any in the genesis file
		if err := acc.PublicKey.Compress(); err != nil {
			app.log.Error("Failed to compress the key")
			panic(err)
		}

		balance := make([]byte, 8)
		binary.BigEndian.PutUint64(balance, acc.Balance)

		dbEntry := prefixKey(accountsPrefix, acc.PublicKey)
		app.state.db.Set(dbEntry, balance)

		b64name := base64.StdEncoding.EncodeToString(acc.PublicKey)
		app.log.Info(fmt.Sprintf("Created new account: %v with starting balance: %v", b64name, acc.Balance))
	}

	// create holdingAccount
	holdingBalance := make([]byte, 8)
	binary.BigEndian.PutUint64(holdingBalance, holdingStartingBalance)
	dbEntry := prefixKey(accountsPrefix, holdingAccountAddress)
	app.state.db.Set(dbEntry, holdingBalance)

	b64name := base64.StdEncoding.EncodeToString(holdingAccountAddress)
	app.log.Info(fmt.Sprintf("Created holdingAccount: %v with starting balance: %v", b64name, holdingStartingBalance))

	numIAs := len(genesisState.CoconutProperties.IssuingAuthorities)
	threshold := genesisState.CoconutProperties.Threshold
	// do not terminate as it is possible (TODO: actually implement it) to add IAs in txs
	if threshold > numIAs {
		app.log.Error(fmt.Sprintf("Only %v Issuing Authorities declared in the genesis block out of minimum %v",
			numIAs, threshold))
		return types.ResponseInitChain{}
	}

	vks := make([]*coconut.VerificationKey, threshold)
	xs := make([]*Curve.BIG, threshold)
	for i, ia := range genesisState.CoconutProperties.IssuingAuthorities {
		if i == threshold {
			break // TODO: choose different subsets of keys
		}
		vk := &coconut.VerificationKey{}
		err := vk.UnmarshalBinary(ia.Vk)
		if err != nil {
			app.log.Error(fmt.Sprintf("Error while unmarshaling genesis IA Verification Key : %v", err))
		}
		xs[i] = Curve.NewBIGint(ia.Id)
		vks[i] = vk
	}
	params, err := coconut.Setup(genesisState.CoconutProperties.MaxAttrs)
	if err != nil {
		// there's no alternative but panic now
		panic(err)
	}
	// EXPLICITLY SET BPGROUP (AND HENCE RNG) TO NIL SINCE IT SHOULD NOT BE USED ANYWAY,
	// BUT IF IT WAS USED ITS UNDETERMINISTIC
	params.G = nil

	// we will need to have access to g1, g2 and hs in order to verify credentials
	// while we can get g1 and g2 from curve params, hs depends on number of attributes
	// so store them; the point are always compressed
	hsb := coconut.ECPSliceToCompressedBytes(params.Hs())
	app.state.db.Set(coconutHs, hsb)
	app.log.Info(fmt.Sprintf("Stored hs in DB"))

	pp := coconut.NewPP(xs)
	avk := coconut.AggregateVerificationKeys(params, vks, pp)
	avkb, err := avk.MarshalBinary()
	if err != nil {
		// there's no alternative but panic now
		panic(err)
	}

	app.state.db.Set(aggregateVkKey, avkb)
	app.log.Info(fmt.Sprintf("Stored Aggregate Verification Key in DB"))

	// dont save state?
	// app.state.db.SaveVersion()
	return types.ResponseInitChain{}
}

func (app *NymApplication) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	fmt.Println("BeginBlock")

	return types.ResponseBeginBlock{}
}

func (app *NymApplication) EndBlock(req types.RequestEndBlock) types.ResponseEndBlock {
	fmt.Println("EndBlock", req.Height)

	return types.ResponseEndBlock{}
}
