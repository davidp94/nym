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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/query"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	cmn "github.com/tendermint/tendermint/libs/common"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/version"
)

// TODO: FIXME: considering tendermint blockchain will no longer have to verify coconut credentials,
// do we still need to keep any information regarding issuers?

const (
	DBNAME                                          = "nymDB"
	DefaultDbDir                                    = "/nymabci"
	createAccountOnDepositIfDoesntExist             = true
	createAccountOnPipeAccountTransferIfDoesntExist = true

	// ProtocolVersion defines version of the protocol used.
	ProtocolVersion version.Protocol = 0x1
)

// nolint: gochecknoglobals
var _ types.Application = (*NymApplication)(nil)

// NymApplication defines basic structure for the Nym-specific ABCI.
type NymApplication struct {
	types.BaseApplication
	state State
	log   log.Logger

	// Version is the semantic version of the ABCI library used.
	Version string

	// AppVersion defines version of the app used. Unless explicitly required,
	// it is going to be the same as ProtocolVersion
	AppVersion uint64

	// CurrentBlock int64 // any point in this at this point?
}

// NewNymApplication initialises Nym-specific Tendermint ABCI.
func NewNymApplication(dbType, dbDir string, logger log.Logger) *NymApplication {
	if dbDir == "" {
		dbDir = DefaultDbDir
	}
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

	app := &NymApplication{
		state:      state,
		log:        logger,
		Version:    version.ABCIVersion,
		AppVersion: ProtocolVersion.Uint64(),
	}

	if app.state.db.Version() > 0 {
		if err := app.loadWatcherThreshold(); err != nil {
			panic(fmt.Errorf("expected to have watcher threshold stored: %v", err))
		}
		if err := app.loadPipeAccountAddress(); err != nil {
			panic(fmt.Errorf("expected to have pipe account address stored: %v", err))
		}
	}

	return app
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
	app.log.Debug(fmt.Sprintf("SetOption; height: %v", app.state.db.Version()))

	return types.ResponseSetOption{}
}

// DeliverTx delivers a tx for full processing.
func (app *NymApplication) DeliverTx(tx []byte) types.ResponseDeliverTx {
	app.log.Debug(fmt.Sprintf("DeliverTx; height: %v", app.state.db.Version()))

	txType := tx[0]
	switch txType {
	// currently for debug purposes to check if given g^s is in the spent set
	case transaction.TxTypeLookUpZeta:
		app.log.Info("DeliverTx for lookup zeta")
		// app.log.Info(fmt.Sprintf("looking up %v", tx[1:]))
		// return types.ResponseDeliverTx{Code: code.OK, Data: app.lookUpZeta(tx[1:])}

	case transaction.TxNewAccount:
		// creates new account
		app.log.Info("New Account tx")
		return app.createNewAccount(tx[1:])

	case transaction.TxTransferBetweenAccounts:
		// DEBUG: transfer funds from account X to account Y
		if !tmconst.DebugMode {
			app.log.Info("Trying to use TxTransferBetweenAccounts not in debug mode")
			break
		}
		app.log.Info("Transfer tx")
		return app.transferFunds(tx[1:])
	case transaction.TxTransferToPipeAccountNotification:
		app.log.Info("Transfer to pipe account notification")
		return app.handleTransferToPipeAccountNotification(tx[1:])
	case transaction.TxDepositCoconutCredential:
		// deposits coconut credential and transforms appropriate amount from pipe to merchant
		app.log.Info("Deposit Credential")
		// return app.depositCoconutCredential(tx[1:])
	case transaction.TxCredentialRequest:
		// removes given amount of tokens from user's account and writes crypto material to the chain
		app.log.Info("Credential request")
		return app.handleCredentialRequest(tx[1:])
	case transaction.TxAdvanceBlock:
		// purely for debug purposes to populate the state and advance the blocks
		if !tmconst.DebugMode {
			app.log.Info("Trying to use TxAdvanceBlock not in debug mode")
			break
		}
		app.log.Info(fmt.Sprintf("storing up %v", tx[1:]))
		app.state.db.Set(tx[1:], []byte{1})

		return types.ResponseDeliverTx{Code: code.OK, Tags: []cmn.KVPair{{Key: []byte{tx[1]}, Value: tx[1:]}}}
	default:
		app.log.Error("Unknown tx")

		return types.ResponseDeliverTx{Code: code.UNKNOWN}
	}

	return types.ResponseDeliverTx{Code: code.UNKNOWN}
}

// CheckTx validates tx in the mempool to discard obviously invalid ones so they would not be included in the block.
func (app *NymApplication) CheckTx(tx []byte) types.ResponseCheckTx {
	app.log.Debug(fmt.Sprintf("CheckTx; height: %v", app.state.db.Version()))

	txType := tx[0]

	switch txType {
	case transaction.TxNewAccount:
		app.log.Debug("CheckTx for TxNewAccount")
		checkCode := app.checkNewAccountTx(tx[1:])
		if checkCode != code.OK {
			app.log.Info(fmt.Sprintf("checkTx for TxNewAccount failed with code: %v - %v",
				checkCode, code.ToString(checkCode)))
		}
		return types.ResponseCheckTx{Code: checkCode}

	case transaction.TxTransferBetweenAccounts:
		app.log.Debug("CheckTx for TxTransferBetweenAccounts")
		checkCode := app.checkTransferBetweenAccountsTx(tx[1:])
		if checkCode != code.OK {
			app.log.Info(fmt.Sprintf("checkTx for TxTransferBetweenAccounts failed with code: %v - %v",
				checkCode, code.ToString(checkCode)))
		}
		return types.ResponseCheckTx{Code: checkCode}
	case transaction.TxTransferToPipeAccountNotification:
		app.log.Debug("CheckTx for TxTransferToPipeAccountNotification")
		checkCode := app.checkTransferToPipeAccountNotificationTx(tx[1:])
		if checkCode != code.OK {
			app.log.Info(fmt.Sprintf("checkTx for TxTransferToPipeAccountNotification failed with code: %v - %v",
				checkCode, code.ToString(checkCode)))
		}
		return types.ResponseCheckTx{Code: checkCode}

	case transaction.TxDepositCoconutCredential:
		app.log.Debug("CheckTx for TxDepositCoconutCredential")

		// checkCode := app.checkDepositCoconutCredentialTx(tx[1:])
		// if checkCode != code.OK {
		// 	app.log.Info(fmt.Sprintf("checkTx for TxTransferBetweenAccounts failed with code: %v - %v",
		// 		checkCode, code.ToString(checkCode)))
		// }
		// return types.ResponseCheckTx{Code: checkCode}
	case transaction.TxAdvanceBlock:
		app.log.Debug("CheckTx for TxAdvanceBlock")
	case transaction.TxCredentialRequest:
		app.log.Debug("CheckTx for TxCredentialRequest")

		checkCode := app.checkCredentialRequestTx(tx[1:])
		if checkCode != code.OK {
			app.log.Info(fmt.Sprintf("checkTx for TxCredentialRequest failed with code: %v - %v",
				checkCode, code.ToString(checkCode)))
		}
		return types.ResponseCheckTx{Code: checkCode}
	default:
		app.log.Error("Unknown Tx")
		return types.ResponseCheckTx{Code: code.INVALID_TX_PARAMS}

	}

	// temp
	checkCode := code.OK
	return types.ResponseCheckTx{Code: checkCode}
}

// Commit commits the state and returns the application Merkle root hash
func (app *NymApplication) Commit() types.ResponseCommit {
	app.log.Debug(fmt.Sprintf("Commit; height: %v", app.state.db.Version()))
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
	app.log.Debug(fmt.Sprintf("Query\n; Path: %v\nData:%v\n", req.Path, req.Data))

	switch req.Path {
	case query.QueryCheckBalancePath:
		return app.checkAccountBalanceQuery(req)
	case query.ZetaStatus:
		return app.checkZeta(req)
	case query.DEBUG_printVk:
		res, err := app.printVk(req)
		if err == tmconst.ErrNotInDebug {
			break
		}
		return res
	default:
		app.log.Info(fmt.Sprintf("Unknown Query Path: %v", req.Path))
	}

	return types.ResponseQuery{Code: code.INVALID_QUERY_PARAMS}
}

// InitChain initialises blockchain with validators and other info from TendermintCore.
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
		app.setAccountBalance(acc.Address[:], acc.Balance)
		app.log.Info(fmt.Sprintf("Created new account: %v with starting balance: %v", acc.Address.Hex(), acc.Balance))
	}

	numWatchers := len(genesisState.EthereumWatchers)
	watcherThreshold := genesisState.SystemProperties.WatcherThreshold
	// In future do not terminate here as it will be possible (TODO: actually implement it) to add IAs in txs
	if watcherThreshold > numWatchers {
		app.log.Error(fmt.Sprintf("Only %v watchers declared in the genesis block out of minimum %v",
			numWatchers, watcherThreshold))
		panic("Insufficient number of issuers declared in the genesis block")
	}

	app.state.watcherThreshold = uint32(watcherThreshold)
	app.storeWatcherThreshold()
	app.state.pipeAccount = genesisState.SystemProperties.PipeAccount
	app.storePipeAccountAddress()

	app.log.Info(fmt.Sprintf("Setting watcher threshold to %v and pipe contract address to %v",
		watcherThreshold, app.state.pipeAccount.Hex()))

	for _, watcher := range genesisState.EthereumWatchers {
		app.storeWatcherKey(watcher)
	}
	app.log.Info("Stored watcher keys in the DB")

	// import vk of IAs
	numIAs := len(genesisState.Issuers)
	threshold := genesisState.SystemProperties.CoconutProperties.Threshold
	// In future do not terminate here as it will be possible (TODO: actually implement it) to add IAs in txs
	if threshold > numIAs {
		app.log.Error(fmt.Sprintf("Only %v Issuing Authorities declared in the genesis block out of minimum %v",
			numIAs, threshold))
		panic("Insufficient number of issuers declared in the genesis block")
	}

	// The seed is not constants between multiple nodes, however, it's not a problem and actually it's a good thing.
	// The nodes should produce the same resultant aggregate verification key regardless of keys used.
	randSource := rand.NewSource(time.Now().UnixNano())
	indices, err := randomInts(threshold, numIAs, randSource)
	if err != nil {
		panic(err) // shouldn't happen due to previous panic
	}

	vks := make([]*coconut.VerificationKey, 0, threshold)
	xs := make([]*Curve.BIG, 0, threshold)

	for _, i := range indices {
		vk := &coconut.ThresholdVerificationKey{}
		if uerr := vk.UnmarshalBinary(genesisState.Issuers[i].VerificationKey); uerr != nil {
			app.log.Error(fmt.Sprintf("Error while unmarshaling genesis IA Verification Key : %v", uerr))
			panic("Failed while unmarshaling genesis verification keys")
		}

		vks = append(vks, vk.VerificationKey)
		// this conversion is safe as on node startup we assert we run in 64bit mode. Plus realistically
		// this value should never even be higher than max of int8
		xs = append(xs, Curve.NewBIGint(int(vk.ID())))
	}

	// TODO: again, do we still need coconut params at this point?
	// generate coconut params required for credential verification later on
	params, err := coconut.Setup(genesisState.SystemProperties.CoconutProperties.MaximumAttributes)
	if err != nil {
		// there's no alternative but panic now
		panic(err)
	}
	// EXPLICITLY SET BPGROUP (AND HENCE RNG) TO NIL SINCE IT SHOULD NOT BE USED ANYWAY,
	// BUT IF IT WAS USED ITS UNDETERMINISTIC
	params.G = nil

	app.storeHs(params.Hs())

	// aggregate the verification keys
	pp := coconut.NewPP(xs)
	avk := coconut.AggregateVerificationKeys(params, vks, pp)
	// TODO: IF we decide nym nodes are going to be verifying credentials,
	// should we also store individual verification keys of all issuers?
	app.storeAggregateVerificationKey(avk)

	// TODO: do we still need it...
	for _, ia := range genesisState.Issuers {
		id := int64(binary.BigEndian.Uint64(ia.VerificationKey)) // first 8 bytes are the id
		app.storeIssuerKey(ia.VerificationKey[8:], id)
	}
	app.log.Info(fmt.Sprintf("Stored IAs Public Keys in DB"))

	// saving app state here causes replay issues, so if app crashes before 1st block is committed it has to
	// redo initchain
	// app.state.db.SaveVersion()
	return types.ResponseInitChain{}
}

// BeginBlock is executed at beginning of each block.
func (app *NymApplication) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	app.log.Debug("BeginBlock")

	return types.ResponseBeginBlock{}
}

// EndBlock is executed at the end of each block. Used to update validator set.
func (app *NymApplication) EndBlock(req types.RequestEndBlock) types.ResponseEndBlock {
	app.log.Debug(fmt.Sprintf("EndBlock; height: %v", req.Height))

	return types.ResponseEndBlock{}
}
