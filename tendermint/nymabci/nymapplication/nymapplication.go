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
	"math/rand"

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
// TODO:
const (
	DBNAME                              = "nymDB"
	createAccountOnDepositIfDoesntExist = true
	holdingStartingBalance              = 100000 // entirely for debug purposes
)

// nolint: gochecknoglobals
var (
	sequenceNumPrefix     = []byte("spent")
	accountsPrefix        = []byte("account")
	holdingAccountAddress = []byte("HOLDING ACCOUNT")
	aggregateVkKey        = []byte("avk")
	coconutHs             = []byte("coconutHs")
	iaKeyPrefix           = []byte("IssuingAuthority")
	commitmentsPrefix     = []byte("commitment")

	// TODO: will need to store all vks

	// ProtocolVersion defines version of the protocol used.
	ProtocolVersion version.Protocol = 0x1
)

// todo: validator updates etc

var _ types.Application = (*NymApplication)(nil)

// GenesisAppState defines the json structure of the the AppState in the Genesis block. This allows parsing it
// and applying appropriate changes to the state upon InitChain.
// Currently it includes list of genesis accounts and Coconut properties required for credential validation.
type GenesisAppState struct {
	Accounts          []account.GenesisAccount `json:"accounts"`
	CoconutProperties struct {
		MaxAttrs           int `json:"q"`
		Threshold          int `json:"threshold"`
		IssuingAuthorities []struct {
			ID        uint32 `json:"id"`
			Vk        []byte `json:"vk"`
			PublicKey []byte `json:"pub_key"`
		} `json:"issuingAuthorities"`
	} `json:"coconutProperties"`
}

// State defines ABCI app state. Currently it is a iavl tree. Reason for the choice: it was recurring case in example.
// It provides height (changes after each save -> perfect for blockchain) + fast hash which is also needed.
type State struct {
	db *iavl.MutableTree // hash and height (version) are obtained from the tree methods
}

// NymApplication defines basic structure for the Nym-specific ABCI.
type NymApplication struct {
	types.BaseApplication
	state State

	log log.Logger

	// Version is the semantic version of the ABCI library used.
	Version string

	// AppVersion defines version of the app used. Unless explicitly required,
	// it is going to be the same as ProtocolVersion
	AppVersion uint64

	// CurrentBlock int64 // any point in this at this point?
}

// NewNymApplication initialises Nym-specific Tendermint ABCI.
func NewNymApplication(dbType, dbDir string, logger log.Logger) *NymApplication {
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

// Info returns the application information. Required by the nodes to sync in case they crashed.
func (app *NymApplication) Info(req types.RequestInfo) types.ResponseInfo {
	res := types.ResponseInfo{
		// Data:             fmt.Sprintf("testmsg"),
		Version:          app.Version,
		AppVersion:       app.AppVersion,
		LastBlockHeight:  app.state.db.Version(),
		LastBlockAppHash: app.state.db.Hash(),
	}

	// app.CurrentBlock = app.state.db.Version() // todo: needed?
	return res
}

// SetOption sets non-consensus critical application specific options.
// Such as fee required for CheckTx, but not DeliverTx as that would be consensus critical.
//
// Currently I'm not sure where it is called or how to do it.
func (app *NymApplication) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	fmt.Println("SetOption; height: ", app.state.db.Version(), req)

	return types.ResponseSetOption{}
}

// currently for debug purposes to check if given g^s is in the spent set
func (app *NymApplication) lookUpZeta(zeta []byte) []byte {
	_, val := app.state.db.Get(zeta)

	if val != nil {
		return []byte{1}
	}
	return []byte{}
}

// DeliverTx delivers a tx for full processing.
func (app *NymApplication) DeliverTx(tx []byte) types.ResponseDeliverTx {
	fmt.Println("DeliverTx; height: ", app.state.db.Version())

	txType := tx[0]
	switch txType {
	// currently for debug purposes to check if given g^s is in the spent set
	case transaction.TxTypeLookUpZeta:
		app.log.Info("DeliverTx for lookup zeta")
		app.log.Info(fmt.Sprintf("looking up %v", tx[1:]))
		return types.ResponseDeliverTx{Code: code.OK, Data: app.lookUpZeta(tx[1:])}

	case transaction.TxNewAccount:
		// creates new account
		app.log.Info("New Account tx")
		return app.createNewAccount(tx[1:])
	case transaction.TxTransferBetweenAccounts:
		// DEBUG: transfer funds from account X to account Y
		app.log.Info("Transfer tx")
		return app.transferFunds(tx[1:])
	case transaction.TxDepositCoconutCredential:
		// deposits coconut credential and transforms appropriate amount from holding to merchant
		app.log.Info("Deposit Credential")
		return app.depositCoconutCredential(tx[1:])
	case transaction.TxTransferToHolding:
		// transfer given amount of client's funds to the holding account
		app.log.Info("Transfer to Holding")
		return app.transferToHolding(tx[1:])
	case transaction.TxAdvanceBlock:
		// purely for debug purposes to populate the state and advance the blocks
		app.log.Info(fmt.Sprintf("storing up %v", tx[1:]))
		app.state.db.Set(tx[1:], []byte{1})

		return types.ResponseDeliverTx{Code: code.OK}
	default:
		app.log.Error("Unknown tx")

		return types.ResponseDeliverTx{Code: code.UNKNOWN}
	}
}

// CheckTx validates tx in the mempool to discard obviously invalid ones so they would not be included in the block.
func (app *NymApplication) CheckTx(tx []byte) types.ResponseCheckTx {
	txType := tx[0]

	switch txType {
	case transaction.TxNewAccount:
		app.log.Debug("CheckTx for TxNewAccount")
	case transaction.TxTransferBetweenAccounts:
		app.log.Debug("CheckTx for TxTransferBetweenAccounts")
	case transaction.TxDepositCoconutCredential:
		app.log.Debug("CheckTx for TxDepositCoconutCredential")
	case transaction.TxAdvanceBlock:
		app.log.Debug("CheckTx for TxAdvanceBlock")
	case transaction.TxTransferToHolding:
		app.log.Debug("CheckTx for TxTransferToHolding")
	default:
		app.log.Error("Default CheckTX")

	}

	checkCode := app.validateTx(tx)
	if checkCode != code.OK {
		app.log.Info("Tx failed CheckTx")
	}

	fmt.Println("CheckTx; height: ", app.state.db.Version())

	return types.ResponseCheckTx{Code: checkCode}
}

// Commit commits the state and returns the application Merkle root hash
func (app *NymApplication) Commit() types.ResponseCommit {
	fmt.Println("Commit; height: ", app.state.db.Version())
	_, _, err := app.state.db.SaveVersion()
	if err != nil {
		app.log.Error(fmt.Sprintf("Error while saving state: %v", err))
		// should we just panic?
	}
	// reset caches etc here
	return types.ResponseCommit{Data: app.state.db.Hash()}
}

// Query queries App State. It is not guaranteed to always give the freshest entries as it is not ordered like txs are.
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
	fmt.Println(req.Path)
	fmt.Println(req.Data)

	return types.ResponseQuery{Code: code.OK}
}

// InitChain initializes blockchain with validators and other info from TendermintCore.
// It also populates genesis appstate with information from the genesis block.
func (app *NymApplication) InitChain(req types.RequestInitChain) types.ResponseInitChain {
	genesisState := &GenesisAppState{}
	if err := json.Unmarshal(req.AppStateBytes, genesisState); err != nil {
		app.log.Error("Failed to unmarshal genesis app state")
		panic(err)
	}
	app.log.Info(fmt.Sprintf("Adding %v genesis accounts", len(genesisState.Accounts)))

	// create genesis accounts
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

	// import vk of IAs
	numIAs := len(genesisState.CoconutProperties.IssuingAuthorities)
	threshold := genesisState.CoconutProperties.Threshold
	// do not terminate as it is possible (TODO: actually implement it) to add IAs in txs
	if threshold > numIAs {
		app.log.Error(fmt.Sprintf("Only %v Issuing Authorities declared in the genesis block out of minimum %v",
			numIAs, threshold))
		return types.ResponseInitChain{}
	}

	// choose pseudorandomly set of keys to use. Each node will produce same result due to constant seed
	// Note: the Time used is that of creation of genesis block, NOT CURRENT TIME AT THE TIME OF CALLING THIS FUNCTION
	randSource := rand.NewSource(req.Time.UnixNano())
	indices := randomInts(threshold, numIAs, randSource)

	vks := make([]*coconut.VerificationKey, 0, threshold)
	xs := make([]*Curve.BIG, 0, threshold)

	for _, i := range indices {
		vk := &coconut.VerificationKey{}
		if err := vk.UnmarshalBinary(genesisState.CoconutProperties.IssuingAuthorities[i].Vk); err != nil {
			app.log.Error(fmt.Sprintf("Error while unmarshaling genesis IA Verification Key : %v", err))
			panic("Failed startup") // Todo: choose new subset
		}

		vks = append(vks, vk)
		xs = append(xs, Curve.NewBIGint(int(genesisState.CoconutProperties.IssuingAuthorities[i].ID)))
	}

	// generate coconut params required for credential verification later on
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

	// aggregate the verification keys
	pp := coconut.NewPP(xs)
	avk := coconut.AggregateVerificationKeys(params, vks, pp)
	avkb, err := avk.MarshalBinary()
	if err != nil {
		// there's no alternative but panic now
		panic(err)
	}

	app.state.db.Set(aggregateVkKey, avkb)
	app.log.Info(fmt.Sprintf("Stored Aggregate Verification Key in DB"))

	// finally save pubkeys of ias (used to verify requests for transferring to holding account)
	for _, ia := range genesisState.CoconutProperties.IssuingAuthorities {
		idb := make([]byte, 4)
		binary.BigEndian.PutUint32(idb, ia.ID)

		dbEntry := prefixKey(iaKeyPrefix, idb)
		app.state.db.Set(dbEntry, ia.PublicKey)
	}
	app.log.Info(fmt.Sprintf("Stored IAs Public Keys in DB"))

	// saving app state here causes replay issues, so if app crashes before 1st block is committed it has to
	// redo initchain
	// app.state.db.SaveVersion()
	return types.ResponseInitChain{}
}

// BeginBlock is executed at beginning of each block.
func (app *NymApplication) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	fmt.Println("BeginBlock")

	return types.ResponseBeginBlock{}
}

// EndBlock is executed at the end of each block. Used to update validator set.
func (app *NymApplication) EndBlock(req types.RequestEndBlock) types.ResponseEndBlock {
	fmt.Println("EndBlock", req.Height)

	return types.ResponseEndBlock{}
}
