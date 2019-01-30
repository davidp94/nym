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
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/query"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/version"
)

const (
	DBNAME = "nymDB"
	zl     = constants.ECPLen
)

var (
	// todo: move vars to appropriate files
	stateKey              = []byte("stateKey")
	zetaPrefix            = []byte("zeta")
	accountsPrefix        = []byte("account")
	holdingAccountAddress = []byte("HOLDING ACCOUNT")

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
func prefixZeta(zeta [zl]byte) [zl + 4]byte {
	// TODO: surely there must be a better syntax for that
	arr := [zl + 4]byte{zetaPrefix[0], zetaPrefix[1], zetaPrefix[2], zetaPrefix[3]}
	copy(arr[4:], zeta[:])

	return arr
}

func prefixKey(prefix []byte, key []byte) []byte {
	b := make([]byte, len(key)+len(prefix))
	copy(b, prefix)
	copy(b[len(prefix):], key)

	return b
}

type State struct {
	db *iavl.MutableTree // hash and height (version) are obtained from the tree methods
}

type NymApplication struct {
	types.BaseApplication
	state State

	// data cache for current block
	zetaCache map[[zl + 4]byte][]byte // unlike slices, arrays can be used as keys in maps
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
		zetaCache:  make(map[[zl + 4]byte][]byte),
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
	fmt.Println("SetOption; height: ", app.state.db.Version())

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
	fmt.Println("DeliverTx:; height: ", app.state.db.Version())

	txType := tx[0]
	switch txType {
	case transaction.TxTypeLookUpZeta:
		app.log.Info("CheckTx for lookup zeta")
		app.log.Info(fmt.Sprintf("looking up %v", tx[1:]))
		present := app.lookUpZeta(tx[1:])
		return types.ResponseDeliverTx{Code: code.OK, Data: present}

	case invalidPrefix:
		app.log.Info("Test Invalid Deliver")
		return types.ResponseDeliverTx{Code: code.UNKNOWN}

	default:
		app.log.Info("default CheckTx")
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
		app.log.Info("CheckTx for lookup zeta")
	default:
		app.log.Info("default CheckTx")
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
	app.zetaCache = make(map[[zl + 4]byte][]byte)
	return types.ResponseCommit{Data: app.state.db.Hash()}
	// return types.ResponseCommit{}
}

func (app *NymApplication) Query(req types.RequestQuery) types.ResponseQuery {
	switch req.Path {
	case query.QueryCheckBalancePath:
		val, code := app.queryBalance(req.Data)
		// TODO: include index (as found in the db)?
		return types.ResponseQuery{Code: code, Key: req.Data, Value: val}
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
	fmt.Println("InitChain")

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
