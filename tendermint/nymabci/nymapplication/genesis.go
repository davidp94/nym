// genesis.go - genesis appstate for Nym ABCI
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

package nymapplication

import (
	ethcommon "github.com/ethereum/go-ethereum/common"
)

type CoconutProperties struct {
	// Defines maximum number of attributes the coconut keys of the issuers can sign.
	MaximumAttributes int `json:"q"`
	// Defines the threshold parameter of the coconut system, i.e. minimum number of issuers required to successfully
	// issue a credential
	Threshold int `json:"threshold"`
}

type Issuer struct {
	// ID of the particular issuer. Has to be the same as during generation of the verification key.
	ID uint32 `json:"id"`
	// While currently Issuers do not need any additional keypair to interact with the blockchain, it might be useful
	// to just leave it in genesis app state would we ever need it down the line.
	PublicKey []byte `json:"pub_key"`
	// The coconut verification key of the particular issuer.
	VerificationKey []byte `json:"vk"`
}

type Watcher struct {
	// Public key associated with given watcher. Used to authenticate any notifications they send to the chain.
	PublicKey []byte `json:"pub_key"`
}

// FIXME: introduce this instead of the current accounts
type GenesisAccount struct {
	Address ethcommon.Address `json:"address"`
	Balance uint64            `json:"balance"`
}

// GenesisAppState defines the json structure of the the AppState in the Genesis block. This allows parsing it
// and applying appropriate changes to the state upon InitChain.
// Currently it includes list of genesis accounts and Coconut properties required for credential validation.
type GenesisAppState struct {
	Accounts          []GenesisAccount  `json:"accounts"`
	CoconutProperties CoconutProperties `json:"coconutProperties"`
	Issuers           []Issuer          `json:"issuingAuthorities"`
	EthereumWatchers  []Watcher         `json:"ethereumWatchers"`

	// CoconutProperties struct {
	// 	MaxAttrs           int `json:"q"`
	// 	Threshold          int `json:"threshold"`
	// 	IssuingAuthorities []struct {
	// 		ID        uint32 `json:"id"`
	// 		Vk        []byte `json:"vk"`
	// 		PublicKey []byte `json:"pub_key"`
	// 	} `json:"issuingAuthorities"`
	// } `json:"coconutProperties"`
}
