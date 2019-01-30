// transaction.go - tx logic
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

// Package transaction defines transaction logic for the Nym application.
package transaction

import (
	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	proto "github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const (
	TxTypeLookUpZeta byte = 0x01
	TxNewAccount     byte = 0x02
)

var (
	// TODO: better alternative
	TruthBytes []byte = []byte("TRUE")
	FalseBytes []byte = []byte("FALSE")
)

type lookUpZetaTx []byte

func NewLookUpZetaTx(zeta *Curve.ECP) []byte {
	tx := make([]byte, 1+constants.ECPLen)
	zb := make([]byte, constants.ECPLen)
	zeta.ToBytes(zb, true)

	tx[0] = TxTypeLookUpZeta
	copy(tx[1:], zb)
	return tx
}

// CreateNewAccountRequest creates new request for tx for new account creation.
func CreateNewAccountRequest(account account.Account, credential []byte) ([]byte, error) {
	msg := make([]byte, len(account.PublicKey)+len(credential))
	copy(msg, account.PublicKey)
	copy(msg[len(account.PublicKey):], credential)
	sig := account.PrivateKey.SignBytes(msg)
	req := &NewAccountRequest{
		PublicKey:  account.PublicKey,
		Credential: credential,
		Sig:        sig,
	}
	protob, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	b := make([]byte, len(protob)+1)
	b[0] = TxNewAccount
	copy(b[1:], protob)
	return b, nil
}
