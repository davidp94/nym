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
	"encoding/binary"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	proto "github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const (
	// TxTypeLookUpZeta is byte prefix for transaction to check for presence of zeta.
	TxTypeLookUpZeta byte = 0x01
	// TxNewAccount is byte prefix for transaction to create new account.
	TxNewAccount byte = 0x02
	// TxTransferBetweenAccounts is byte prefix for transaction to transfer funds between 2 accounts. for debug
	TxTransferBetweenAccounts byte = 0x03
	// TxTransferToHolding is byte prefix for transaction to transfer client's funds to holding account.
	TxTransferToHolding byte = 0x04
	// TxDepositCoconutCredential is byte prefix for transaction to deposit a coconut credential (+ transfer funds).
	TxDepositCoconutCredential byte = 0xa0
	// TxAdvanceBlock is byte prefix for transaction to store entire tx block in db to advance the blocks.
	TxAdvanceBlock byte = 0xff // entirely for debug purposes
)

// NewLookUpZetaTx creates new request for tx to lookup provided zeta.
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

// CreateNewTransferRequest creates new request for tx to transfer funds from one account to another.
// Currently and possibly only for debug purposes
// to freely transfer tokens between accounts to setup different scenarios.
func CreateNewTransferRequest(account account.Account, target account.ECPublicKey, amount uint64) ([]byte, error) {
	msg := make([]byte, len(account.PublicKey)+len(target)+8)
	copy(msg, account.PublicKey)
	copy(msg[len(account.PublicKey):], target)
	binary.BigEndian.PutUint64(msg[len(account.PublicKey)+len(target):], amount)

	sig := account.PrivateKey.SignBytes(msg)
	req := &AccountTransferRequest{
		SourcePublicKey: account.PublicKey,
		TargetPublicKey: target,
		Amount:          amount,
		Sig:             sig,
	}
	protob, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	b := make([]byte, len(protob)+1)
	b[0] = TxTransferBetweenAccounts
	copy(b[1:], protob)
	return b, nil
}

// CreateNewDepositCoconutCredentialRequest creates new request for tx to send credential created out of given token
// (that is bound to particular merchant address) to be spent.
func CreateNewDepositCoconutCredentialRequest(
	params *coconut.Params,
	avk *coconut.VerificationKey,
	sig *coconut.Signature,
	token *token.Token,
	address []byte,
) ([]byte, error) {
	pubM, privM := token.GetPublicAndPrivateSlices()

	theta, err := coconut.ShowBlindSignatureTumbler(params, avk, sig, privM, address)
	if err != nil {
		return nil, err
	}

	protoSig, err := sig.ToProto()
	if err != nil {
		return nil, err
	}

	pubMb, err := coconut.BigSliceToByteSlices(pubM)
	if err != nil {
		return nil, err
	}

	protoThetaTumbler, err := theta.ToProto()
	if err != nil {
		return nil, err
	}

	req := &DepositCoconutCredentialRequest{
		Sig:             protoSig,
		PubM:            pubMb,
		Theta:           protoThetaTumbler,
		Value:           token.Value(),
		MerchantAddress: address,
	}

	protob, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	b := make([]byte, len(protob)+1)

	b[0] = TxDepositCoconutCredential
	copy(b[1:], protob)
	return b, nil
}

// CreateNewTransferToHoldingRequest creates new request for tx to transfer funds from user's account
// to the holding account.
// It is designed to be executed by the user itself.
func CreateNewTransferToHoldingRequest(acc account.Account, amount uint32, nonce []byte) ([]byte, error) {
	msg := make([]byte, len(acc.PublicKey)+len(tmconst.HoldingAccountAddress)+4+len(nonce))
	copy(msg, acc.PublicKey)
	copy(msg[len(acc.PublicKey):], tmconst.HoldingAccountAddress)
	binary.BigEndian.PutUint32(msg[len(acc.PublicKey)+len(tmconst.HoldingAccountAddress):], amount)
	copy(msg[len(acc.PublicKey)+len(tmconst.HoldingAccountAddress)+4:], nonce)
	sig := acc.PrivateKey.SignBytes(msg)

	req := &TransferToHoldingRequest{
		SourcePublicKey: acc.PublicKey,
		TargetAddress:   tmconst.HoldingAccountAddress,
		Amount:          amount,
		Nonce:           nonce,
		Sig:             sig,
	}

	protob, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	b := make([]byte, len(protob)+1)

	b[0] = TxTransferToHolding
	copy(b[1:], protob)
	return b, nil
}

// DEPRECATED; but left temporarly for reference sake
// // CreateNewTransferToHoldingRequest creates new request for tx to transfer funds from client's account
// // to the holding account.
// // It is designed to be executed by an issuing authority.
// func CreateNewTransferToHoldingRequest(params TransferToHoldingReqParams) ([]byte, error) {
// 	id := params.ID
// 	priv := params.PrivateKey
// 	clientPublicKey := params.ClientPublicKey
// 	amount := params.Amount
// 	commitment := params.Commitment
// 	clientSig := params.ClientSig

// 	msg := make([]byte, 4+len(clientPublicKey)+4+len(commitment)+len(clientSig))
// 	binary.BigEndian.PutUint32(msg, id)
// 	copy(msg[4:], clientPublicKey)
// 	binary.BigEndian.PutUint32(msg[4+len(clientPublicKey):], uint32(amount))
// 	copy(msg[4+len(clientPublicKey)+4:], commitment)
// 	copy(msg[4+len(clientPublicKey)+4+len(commitment):], clientSig)

// 	sig := priv.SignBytes(msg)

// 	req := &TransferToHoldingRequest{
// 		IAID:            id,
// 		ClientPublicKey: clientPublicKey,
// 		Amount:          amount,
// 		Commitment:      commitment,
// 		ClientSig:       clientSig,
// 		IASig:           sig,
// 	}

// 	protob, err := proto.Marshal(req)
// 	if err != nil {
// 		return nil, err
// 	}
// 	b := make([]byte, len(protob)+1)

// 	b[0] = TxTransferToHolding
// 	copy(b[1:], protob)
// 	return b, nil
// }
