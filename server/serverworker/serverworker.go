// serverworker.go - Worker for Coconut server.
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

// Package serverworker gives additional functionalities to regular CoconutWorker
// that are required by a server instance.
package serverworker

import (
	"bytes"
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"
	nymclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"gopkg.in/op/go-logging.v1"
)

const (
	defaultErrorMessage    = ""
	defaultErrorStatusCode = commands.StatusCode_UNKNOWN

	providerStartupErr = "The aggregate verification key is nil. " +
		"Is the server a provider? And if so, has it completed the start up sequence?"
)

// ServerWorker allows writing coconut actions to a shared job queue,
// so that they could be run concurrently.
type ServerWorker struct {
	worker.Worker
	*coconutworker.CoconutWorker // TODO: since coconutWorker is created in New, does it need to be a reference?

	incomingCh <-chan *commands.CommandRequest
	log        *logging.Logger

	nymClient *nymclient.Client
	store     *storage.Database

	iaid       uint32
	sk         *coconut.SecretKey // ensure they can be safely shared between multiple workers
	vk         *coconut.VerificationKey
	avk        *coconut.VerificationKey // only used if server is a provider
	nymAccount account.Account

	id uint64
}

func getDefaultResponse() *commands.Response {
	return &commands.Response{
		Data:         nil,
		ErrorStatus:  defaultErrorStatusCode,
		ErrorMessage: defaultErrorMessage,
	}
}

func (sw *ServerWorker) setErrorResponse(response *commands.Response, errMsg string, errCode commands.StatusCode) {
	sw.log.Error(errMsg)
	response.Data = nil
	response.ErrorMessage = errMsg
	response.ErrorStatus = errCode
}

func (sw *ServerWorker) handleSignRequest(req *commands.SignRequest) *commands.Response {
	response := getDefaultResponse()

	if len(req.PubM) > len(sw.sk.Y()) {
		errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports."+
			" Got: %v, expected at most: %v", len(req.PubM), len(sw.sk.Y()))
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	sig, err := sw.SignWrapper(sw.sk, coconut.BigSliceFromByteSlices(req.PubM))
	if err != nil {
		// TODO: should client really know those details?
		errMsg := fmt.Sprintf("Error while signing message: %v", err)
		sw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	sw.log.Debugf("Writing back signature")
	response.Data = sig
	return response
}

func (sw *ServerWorker) handleVerificationKeyRequest(req *commands.VerificationKeyRequest) *commands.Response {
	response := getDefaultResponse()
	response.Data = sw.vk
	return response
}

func (sw *ServerWorker) handleVerifyRequest(req *commands.VerifyRequest) *commands.Response {
	response := getDefaultResponse()

	if sw.avk == nil {
		errMsg := providerStartupErr
		sw.setErrorResponse(response, errMsg, commands.StatusCode_UNAVAILABLE)
		return response
	}
	sig := &coconut.Signature{}
	if err := sig.FromProto(req.Sig); err != nil {
		errMsg := "Could not recover received signature."
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	response.Data = sw.VerifyWrapper(sw.avk, coconut.BigSliceFromByteSlices(req.PubM), sig)
	return response
}

func (sw *ServerWorker) handleBlindSignRequest(req *commands.BlindSignRequest) *commands.Response {
	response := getDefaultResponse()

	lambda := &coconut.Lambda{}
	if err := lambda.FromProto(req.Lambda); err != nil {
		errMsg := "Could not recover received lambda."
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	if len(req.PubM)+len(lambda.Enc()) > len(sw.sk.Y()) {
		errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports."+
			" Got: %v, expected at most: %v", len(req.PubM)+len(lambda.Enc()), len(sw.sk.Y()))
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	egPub := &elgamal.PublicKey{}
	if err := egPub.FromProto(req.EgPub); err != nil {
		errMsg := "Could not recover received ElGamal Public Key."
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	sig, err := sw.BlindSignWrapper(sw.sk, lambda, egPub, coconut.BigSliceFromByteSlices(req.PubM))
	if err != nil {
		// TODO: should client really know those details?
		errMsg := fmt.Sprintf("Error while signing message: %v", err)
		sw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	sw.log.Debugf("Writing back blinded signature")
	response.Data = sig
	return response
}

func (sw *ServerWorker) handleBlindVerifyRequest(req *commands.BlindVerifyRequest) *commands.Response {
	response := getDefaultResponse()

	if sw.avk == nil {
		errMsg := providerStartupErr
		sw.setErrorResponse(response, errMsg, commands.StatusCode_UNAVAILABLE)
		return response
	}
	sig := &coconut.Signature{}
	if err := sig.FromProto(req.Sig); err != nil {
		errMsg := "Could not recover received signature."
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	theta := &coconut.Theta{}
	if err := theta.FromProto(req.Theta); err != nil {
		errMsg := "Could not recover received theta."
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	response.Data = sw.BlindVerifyWrapper(sw.avk, sig, theta, coconut.BigSliceFromByteSlices(req.PubM))
	return response
}

func (sw *ServerWorker) handleSpendCredentialRequest(req *commands.SpendCredentialRequest) *commands.Response {
	response := getDefaultResponse()
	response.Data = false

	// theoretically provider does not need to do any checks as if the request is invalid the blockchain will reject it,
	// but we check if the user says it bound it to our address
	address := req.MerchantAddress

	if bytes.Compare(address, sw.nymAccount.PublicKey) != 0 {
		// check if perhaps our address is in uncompressed form but client bound it to the compressed version
		var accountCompressed account.ECPublicKey = make([]byte, len(sw.nymAccount.PublicKey))
		copy(accountCompressed, sw.nymAccount.PublicKey)
		// nolint: gosec
		accountCompressed.Compress()

		if bytes.Compare(address, accountCompressed) != 0 {
			errMsg := "Request is bound to an invalid address"
			sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_BINDING)
			return response
		}
	}

	blockchainRequest, err := transaction.CreateNewDepositCoconutCredentialRequest(
		req.Sig,
		req.PubM,
		req.Theta,
		req.Value,
		req.MerchantAddress,
	)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to create blockchain request: %v", err)
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	blockchainResponse, err := sw.nymClient.Broadcast(blockchainRequest)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to send transaction to the blockchain: %v", err)
		sw.log.Critical(errMsg)
		response.Data = nil
		response.ErrorMessage = errMsg
		response.ErrorStatus = commands.StatusCode_UNAVAILABLE
		return response
	}

	sw.log.Notice("Received response from the blockchain. Return code: %v; Additional Data: %v",
		code.ToString(blockchainResponse.DeliverTx.Code), string(blockchainResponse.DeliverTx.Data))

	if blockchainResponse.DeliverTx.Code != code.OK {
		errMsg := fmt.Sprintf("The transaction failed to be included on the blockchain. Errorcode: %v - %v",
			blockchainResponse.DeliverTx.Code, code.ToString(blockchainResponse.DeliverTx.Code))
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_TRANSACTION)
		return response
	}

	// the response data in future might be provider dependent, to include say some authorization token
	response.ErrorStatus = commands.StatusCode_OK
	response.Data = true
	return response
}

func (sw *ServerWorker) handleGetCredentialRequest(req *commands.GetCredentialRequest) *commands.Response {
	// IMPLEMENTATION CHANGED: user is responsible for triggering transfer
	response := getDefaultResponse()
	response.ErrorStatus = commands.StatusCode_UNAVAILABLE
	response.ErrorMessage = "This endpoint is no longer available"

	return response

	// below code is temporarily left for the reference sake.

	// any prior checks on the actual request would go here:

	// lambda := &coconut.Lambda{}
	// if err := lambda.FromProto(req.Lambda); err != nil {
	// 	errMsg := "Could not recover received lambda."
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
	// 	return response
	// }
	// if len(req.PubM)+len(lambda.Enc()) > len(sw.sk.Y()) {
	// 	errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports."+
	// 		" Got: %v, expected at most: %v", len(req.PubM)+len(lambda.Enc()), len(sw.sk.Y()))
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
	// 	return response
	// }
	// egPub := &elgamal.PublicKey{}
	// if err := egPub.FromProto(req.EgPub); err != nil {
	// 	errMsg := "Could not recover received ElGamal Public Key."
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
	// 	return response
	// }

	// // before we can issue credential we need to check if the user actually performed a valid transfer to the holding
	// // account
	// // FIXME: we are not performing any checks if this txHash was used before, etc.

	// // first check the sig on request
	// var userPub account.ECPublicKey = req.PublicKey

	// msg := make([]byte, len(req.PublicKey)+4+len(req.Nonce)+len(req.TxHash))
	// copy(msg, req.PublicKey)
	// binary.BigEndian.PutUint32(msg[len(req.PublicKey):], uint32(req.Value))
	// copy(msg[len(req.PublicKey)+4:], req.Nonce)
	// copy(msg[len(req.PublicKey)+4+len(req.Nonce):], req.TxHash)

	// if !userPub.VerifyBytes(msg, req.Sig) {
	// 	errMsg := "Failed to validate the request"
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_SIGNATURE)
	// 	return response
	// }

	// txRex, err := sw.nymClient.TxByHash(req.TxHash)
	// if err != nil {
	// 	errMsg := fmt.Sprintf("Failed to Query the chain: %v", err)
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_UNKNOWN)
	// 	return response
	// }

	// userPub.Compress()

	// // tag is (pub||nonce - value)
	// expectedTagKey := make([]byte, len(userPub)+len(req.Nonce))
	// copy(expectedTagKey, userPub)
	// copy(expectedTagKey[len(userPub):], req.Nonce)

	// expectedTagValue := make([]byte, 4)
	// binary.BigEndian.PutUint32(expectedTagValue, uint32(req.Value))

	// txSuccessful := false
	// for _, tag := range txRex.TxResult.Tags {
	// 	// this is our tag
	// 	if bytes.Compare(tag.Key, expectedTagKey) == 0 {
	// 		if bytes.Compare(tag.Value, expectedTagValue) == 0 {
	// 			txSuccessful = true
	// 			sw.log.Debug("Found matching tags in the tx")
	// 		} else {
	// 			break
	// 		}
	// 	}
	// }

	// if !txSuccessful {
	// 	errMsg := "Tx not included in the chain (or failed to be executed)"
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_TX_NOT_ON_CHAIN)
	// 	return response
	// }

	// // everything is valid now - issue the partial credential
	// sig, err := sw.BlindSignWrapper(sw.sk, lambda, egPub, coconut.BigSliceFromByteSlices(req.PubM))
	// if err != nil {
	// 	// TODO: should client really know those details?
	// 	errMsg := fmt.Sprintf("Error while signing message: %v", err)
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
	// 	return response
	// }

	// sw.log.Debugf("Writing back blinded signature")
	// response.Data = sig
	// return response
}

func (sw *ServerWorker) handleLookUpCredentialRequest(req *commands.LookUpCredentialRequest) *commands.Response {
	response := getDefaultResponse()
	if sw.store.GetHighest() < req.Height {
		errMsg := "Target height hasn't been processed yet."
		sw.setErrorResponse(response, errMsg, commands.StatusCode_NOT_PROCESSED_YET)
		return response
	}

	credPair := sw.store.GetCredential(req.Height, req.Gamma)
	if len(credPair.Credential) <= 0 {
		errMsg := "Could not lookup the credential using provided arguments"
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	response.Data = credPair
	return response
}

func (sw *ServerWorker) handleLookUpBlockCredentialsRequest(req *commands.LookUpBlockCredentialsRequest,
) *commands.Response {
	response := getDefaultResponse()
	if sw.store.GetHighest() < req.Height {
		errMsg := "Target height hasn't been processed yet."
		sw.setErrorResponse(response, errMsg, commands.StatusCode_NOT_PROCESSED_YET)
		return response
	}

	credPairs := sw.store.GetBlockCredentials(req.Height)
	if len(credPairs) <= 0 {
		errMsg := "Could not lookup the credential using provided arguments. " +
			"Either there were no valid txs in this block or it wasn't processed yet."
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	response.Data = credPairs
	return response
}

func (sw *ServerWorker) worker() {
	for {
		select {
		case <-sw.HaltCh():
			sw.log.Noticef("Halting Coconut Server worker %d\n", sw.id)
			return
		case cmdReq := <-sw.incomingCh:
			cmd := cmdReq.Cmd()
			var response *commands.Response

			switch req := cmd.(type) {
			case *commands.SignRequest:
				sw.log.Notice("Received Sign (NOT blind) command")
				response = sw.handleSignRequest(req)

			case *commands.VerificationKeyRequest:
				sw.log.Notice("Received Get Verification Key command")
				response = sw.handleVerificationKeyRequest(req)

			case *commands.VerifyRequest:
				sw.log.Notice("Received Verify (NOT blind) command")
				response = sw.handleVerifyRequest(req)

			case *commands.BlindSignRequest:
				sw.log.Notice("Received Blind Sign command")
				response = sw.handleBlindSignRequest(req)

			case *commands.BlindVerifyRequest:
				sw.log.Notice("Received Blind Verify Command")
				response = sw.handleBlindVerifyRequest(req)

			case *commands.GetCredentialRequest:
				sw.log.Notice("Received Get Credential Command")
				response = sw.handleGetCredentialRequest(req)

			case *commands.SpendCredentialRequest:
				sw.log.Notice("Received Spend Credential Command")
				response = sw.handleSpendCredentialRequest(req)

			case *commands.LookUpCredentialRequest:
				sw.log.Notice("Received Look Up Credential Command")
				response = sw.handleLookUpCredentialRequest(req)

			case *commands.LookUpBlockCredentialsRequest:
				sw.log.Notice("Received Look Up Block Credentials Command")
				response = sw.handleLookUpBlockCredentialsRequest(req)

			default:
				errMsg := "Received Invalid Command"
				sw.log.Warning(errMsg)
				response = getDefaultResponse()
				response.ErrorStatus = commands.StatusCode_INVALID_COMMAND
			}
			cmdReq.RetCh() <- response
		}
	}
}

// Config encapsulates arguments passed in New to create new instance of the serverworker.
type Config struct {
	JobQueue   chan<- *jobpacket.JobPacket
	IncomingCh <-chan *commands.CommandRequest

	ID uint64

	Log *logger.Logger

	NymClient *nymclient.Client
	Store     *storage.Database

	Params *coconut.Params
	IAID   uint32
	Sk     *coconut.SecretKey
	Vk     *coconut.VerificationKey
	Avk    *coconut.VerificationKey
	// NymAccount account.Account
}

// New creates new instance of a serverWorker.
func New(cfg *Config) (*ServerWorker, error) {
	sw := &ServerWorker{
		CoconutWorker: coconutworker.New(cfg.JobQueue, cfg.Params),
		incomingCh:    cfg.IncomingCh,
		id:            cfg.ID,
		iaid:          cfg.IAID,
		sk:            cfg.Sk,
		vk:            cfg.Vk,
		avk:           cfg.Avk,
		nymClient:     cfg.NymClient,
		store:         cfg.Store,
		// nymAccount:    cfg.NymAccount,
		log: cfg.Log.GetLogger(fmt.Sprintf("Serverworker:%d", int(cfg.ID))),
	}

	sw.Go(sw.worker)
	return sw, nil
}
