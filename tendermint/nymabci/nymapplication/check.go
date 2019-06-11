// check.go - CheckTx logic for Tendermint ABCI for Nym
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
	"bytes"
	"encoding/binary"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// implementation will be IP-specific
func (app *NymApplication) verifyCredential(cred []byte) bool {
	return true
}

func (app *NymApplication) validateTransfer(inAddr, outAddr []byte, amount uint64) (uint32, []byte) {
	if len(inAddr) != ethcommon.AddressLength {
		return code.MALFORMED_ADDRESS, []byte("SOURCE")
	}
	if len(outAddr) != ethcommon.AddressLength {
		return code.MALFORMED_ADDRESS, []byte("TARGET")
	}
	// don't allow transfer when addresses are identical because nothing would happen anyway...
	if bytes.Equal(inAddr, outAddr) {
		return code.SELF_TRANSFER, nil
	}

	sourceBalance, err := app.retrieveAccountBalance(inAddr)
	if err != nil {
		return code.ACCOUNT_DOES_NOT_EXIST, []byte("SOUCE")
	}

	if sourceBalance < amount { // + some gas?
		return code.INSUFFICIENT_BALANCE, nil
	}

	if _, err := app.retrieveAccountBalance(outAddr); err != nil {
		return code.ACCOUNT_DOES_NOT_EXIST, []byte("TARGET")
	}

	return code.OK, nil
}

// the tx prefix was removed
func (app *NymApplication) checkNewAccountTx(tx []byte) uint32 {
	req := &transaction.NewAccountRequest{}

	if err := proto.Unmarshal(tx, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return code.INVALID_TX_PARAMS
	}

	if len(req.Address) != ethcommon.AddressLength {
		return code.INVALID_TX_PARAMS
	}

	if !app.verifyCredential(req.Credential) {
		app.log.Info("Failed to verify IP credential")
		return code.INVALID_CREDENTIAL
	}

	msg := make([]byte, len(req.Address)+len(req.Credential))
	copy(msg, req.Address)
	copy(msg[len(req.Address):], req.Credential)

	recPub, err := ethcrypto.SigToPub(tmconst.HashFunction(msg), req.Sig)
	if err != nil {
		app.log.Info("Error while trying to recover public key associated with the signature")
		return code.INVALID_SIGNATURE
	}

	recAddr := ethcrypto.PubkeyToAddress(*recPub)
	if !bytes.Equal(recAddr[:], req.Address) {
		app.log.Info("Failed to verify signature on request")
		return code.INVALID_SIGNATURE
	}

	return code.OK
}

func (app *NymApplication) checkTransferBetweenAccountsTx(tx []byte) uint32 {
	req := &transaction.AccountTransferRequest{}

	if err := proto.Unmarshal(tx, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return code.INVALID_TX_PARAMS
	}

	if app.checkNonce(req.Nonce, req.SourceAddress) {
		return code.REPLAY_ATTACK_ATTEMPT
	}

	if retCode, _ := app.validateTransfer(req.SourceAddress, req.TargetAddress, req.Amount); retCode != code.OK {
		return retCode
	}

	msg := make([]byte, 2*ethcommon.AddressLength+tmconst.NonceLength+8)
	i := copy(msg, req.SourceAddress)
	i += copy(msg[i:], req.TargetAddress)
	binary.BigEndian.PutUint64(msg[i:], req.Amount)
	i += 8
	copy(msg[i:], req.Nonce)

	recPub, err := ethcrypto.SigToPub(tmconst.HashFunction(msg), req.Sig)
	if err != nil {
		app.log.Info("Error while trying to recover public key associated with the signature")
		return code.INVALID_SIGNATURE
	}

	recAddr := ethcrypto.PubkeyToAddress(*recPub)
	if !bytes.Equal(recAddr[:], req.SourceAddress) {
		app.log.Info("Failed to verify signature on request")
		return code.INVALID_SIGNATURE
	}

	return code.OK
}

func (app *NymApplication) checkTransferToPipeAccountNotificationTx(tx []byte) uint32 {
	req := &transaction.TransferToPipeAccountNotification{}

	if err := proto.Unmarshal(tx, req); err != nil {
		app.log.Info("Failed to unmarshal request")
		return code.INVALID_TX_PARAMS
	}

	// first check if the threshold was alredy reached and transaction was committed
	if app.getNotificationCount(req.TxHash) == app.state.watcherThreshold {
		app.log.Info("Already reached required threshold")
		return code.ALREADY_COMMITTED
	}

	// check if the watcher can be trusted
	if !app.checkWatcherKey(req.WatcherPublicKey) {
		app.log.Info("This watcher is not in the trusted set")
		return code.ETHEREUM_WATCHER_DOES_NOT_EXIST
	}

	// check if client address is correctly formed
	if len(req.ClientAddress) != ethcommon.AddressLength {
		app.log.Info("Client's address is malformed")
		return code.MALFORMED_ADDRESS
	}

	// check if the pipe account matches
	if !bytes.Equal(app.state.pipeAccount[:], req.PipeAccountAddress) {
		app.log.Info("The specified pipe account is different from the expected one")
		return code.INVALID_PIPE_ACCOUNT
	}

	// check signature
	msg := make([]byte, len(req.WatcherPublicKey)+2*ethcommon.AddressLength+8+ethcommon.HashLength)
	i := copy(msg, req.WatcherPublicKey)
	i += copy(msg[i:], req.ClientAddress)
	i += copy(msg[i:], req.PipeAccountAddress)
	binary.BigEndian.PutUint64(msg[i:], req.Amount)
	i += 8
	copy(msg[i:], req.TxHash)

	sig := req.Sig
	// last byte is a recoveryID which we don't care about
	if len(sig) > 64 {
		sig = sig[:64]
	}

	if !ethcrypto.VerifySignature(req.WatcherPublicKey, tmconst.HashFunction(msg), sig) {
		app.log.Info("The signature on message is invalid")
		return code.INVALID_SIGNATURE
	}

	// check if this tx was not already confirmed by this watcher
	if app.checkWatcherNotification(req.WatcherPublicKey, req.TxHash) {
		app.log.Info("This watcher already sent this notification before")
		return code.ALREADY_CONFIRMED
	}

	return code.OK
}

// We can't do many checks on the tx without actually initiating it first
func (app *NymApplication) checkDepositCoconutCredentialTx(tx []byte) uint32 {
	req := &transaction.DepositCoconutCredentialRequest{}

	if err := proto.Unmarshal(tx, req); err != nil {
		return code.INVALID_TX_PARAMS
	}

	if len(req.ProviderAddress) != ethcommon.AddressLength {
		return code.INVALID_MERCHANT_ADDRESS
	}

	if !app.checkIfAccountExists(req.ProviderAddress) {
		if !createAccountOnDepositIfDoesntExist {
			app.log.Error("Provider's account doesnt exist")
			return code.MERCHANT_DOES_NOT_EXIST
		}
		// checkTx will not try creating the account for obvious reasons, only deliverTx can do it
	}

	// check for double spending -
	// if credential was already spent, there is no point in any further checks
	if app.checkIfZetaIsSpent(req.Theta.Zeta) {
		return code.DOUBLE_SPENDING_ATTEMPT
	}

	// Just check if data is formed correctly, i.e. it can be unmarshalled
	cred := &coconut.Signature{}
	if err := cred.FromProto(req.Sig); err != nil {
		return code.INVALID_TX_PARAMS
	}

	theta := &coconut.ThetaTumbler{}
	if err := theta.FromProto(req.Theta); err != nil {
		return code.INVALID_TX_PARAMS
	}

	if _, err := coconut.BigSliceFromByteSlices(req.PubM); err != nil {
		return code.INVALID_TX_PARAMS
	}

	return code.OK
}

func (app *NymApplication) checkCredentialRequestTx(tx []byte) uint32 {
	// verify sigs and check if all structs can be unmarshalled
	req := &transaction.CredentialRequest{}
	if err := proto.Unmarshal(tx, req); err != nil {
		return code.INVALID_TX_PARAMS
	}

	// firstly check if client's account even exists and if it has sufficient balance
	if accBalance, err := app.retrieveAccountBalance(req.ClientAddress); err != nil || accBalance < uint64(req.Value) {
		return code.INSUFFICIENT_BALANCE
	}

	// TODO: allow credentials of 0 value as some kind of 'access' tokens?
	// perhaps return to the idea later
	if !token.ValidateValue(req.Value) {
		return code.INVALID_VALUE
	}

	if len(req.CryptoMaterials.PubM) == 0 ||
		len(req.CryptoMaterials.PubM[0]) != constants.BIGLen ||
		Curve.Comp(Curve.FromBytes(req.CryptoMaterials.PubM[0]), Curve.NewBIGint(int(req.Value))) != 0 {
		return code.INVALID_TX_PARAMS
	}

	// used to check only if the data can be recovered
	blindSignMaterials := &coconut.BlindSignMaterials{}
	if err := blindSignMaterials.FromProto(req.CryptoMaterials); err != nil {
		return code.INVALID_TX_PARAMS
	}

	materialsBytes, err := req.CryptoMaterials.OneWayToBytes()
	if err != nil {
		return code.INVALID_TX_PARAMS
	}

	if app.checkNonce(req.Nonce, req.ClientAddress) {
		return code.REPLAY_ATTACK_ATTEMPT
	}

	msg := make([]byte, 2*ethcommon.AddressLength+len(materialsBytes)+8+tmconst.NonceLength)
	i := copy(msg, req.ClientAddress)
	i += copy(msg[i:], app.state.pipeAccount[:])
	i += copy(msg[i:], materialsBytes)
	binary.BigEndian.PutUint64(msg[i:], uint64(req.Value))
	i += 8
	copy(msg[i:], req.Nonce)

	recPub, err := ethcrypto.SigToPub(tmconst.HashFunction(msg), req.Sig)
	if err != nil {
		app.log.Info("Error while trying to recover public key associated with the signature")
		return code.INVALID_SIGNATURE
	}

	recAddr := ethcrypto.PubkeyToAddress(*recPub)
	if !bytes.Equal(recAddr[:], req.ClientAddress) {
		app.log.Info("Failed to verify signature on request")
		return code.INVALID_SIGNATURE
	}

	return code.OK
}
