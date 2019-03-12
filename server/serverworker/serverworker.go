// serverworker.go - Worker for Coconut server.
// Copyright (C) 2018  Jedrzej Stuczynski.
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
	"encoding/base64"
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/common/utils"
	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/logger"
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

	nymClient               *nymclient.Client
	blockchainNodeAddresses []string // we keep them for the future so that if the node we are connected to fails,
	// we could try to reconnect to a different one
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

func (sw *ServerWorker) handleGetCredentialRequest(req *commands.GetCredentialRequest) *commands.Response {
	// any prior checks on the actual request would go here:

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

	// before we can issue credential we need to check if the request is valid on the blockchain side and if so,
	// transfer the specified amount of user's tokens to the holding account
	reqParams := transaction.TransferToHoldingReqParams{
		ID:              sw.iaid,
		PrivateKey:      sw.nymAccount.PrivateKey,
		ClientPublicKey: req.PublicKey,
		Amount:          req.Value,
		Commitment:      req.Lambda.Cm,
		ClientSig:       req.Sig,
	}

	blockchainRequest, err := transaction.CreateNewTransferToHoldingRequest(reqParams)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to create blockchain request: %v", err)
		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	b64name := base64.StdEncoding.EncodeToString(req.PublicKey)
	if len(req.PublicKey) != constants.ECPLen {
		tmp, err := utils.CompressECPBytes(req.PublicKey)
		if err != nil {
			// should we continue or return error without trying to call blockchain?
			// if compression failed it means the address is invalid so blockchain operation WILL FAIL because
			// it can't possibly transfer any funds from an invalid account...
			sw.log.Errorf("Failed to compress %v; address is invalid", b64name)
		}
		b64name = base64.StdEncoding.EncodeToString(tmp)
	}

	sw.log.Notice("Sending request to transfer %v funds from %v to the holding account", req.Value, b64name)

	// TODO: should we wait until tx is actually included in the block or just to hear it was valid? i.e.
	// to wait for deliver_tx to happen or just check_tx
	blockchainResponse, err := sw.nymClient.Broadcast(blockchainRequest)
	if err != nil {
		// should we terminate? If we can't communicate with the blockchain we can't issue any credentials
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

			default:
				errMsg := "Received Invalid Command"
				sw.log.Critical(errMsg)
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

	Params     *coconut.Params
	IAID       uint32
	Sk         *coconut.SecretKey
	Vk         *coconut.VerificationKey
	Avk        *coconut.VerificationKey
	NymAccount account.Account
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
		nymAccount:    cfg.NymAccount,
		log:           cfg.Log.GetLogger(fmt.Sprintf("Serverworker:%d", int(cfg.ID))),
	}

	sw.Go(sw.worker)
	return sw, nil
}