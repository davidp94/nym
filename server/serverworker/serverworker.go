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
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	nymclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"gopkg.in/op/go-logging.v1"
)

// TODO: perhaps replace all "handle" methods with hundlerFuncs similar to net/http ?

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
	incomingCh                   <-chan *commands.CommandRequest
	log                          *logging.Logger
	nymClient                    *nymclient.Client
	store                        *storage.Database
	id                           uint64
}

type IssuerWorker struct {
	*ServerWorker
	iaid uint32
	sk   *coconut.SecretKey
	vk   *coconut.VerificationKey
}

type ProviderWorker struct {
	*ServerWorker
	avk *coconut.VerificationKey
}

func (sw *ServerWorker) getDefaultResponse() *commands.Response {
	return &commands.Response{
		Data:         nil,
		ErrorStatus:  defaultErrorStatusCode,
		ErrorMessage: defaultErrorMessage,
	}
}

func (sw *ServerWorker) setErrorResponse(response *commands.Response, errMsg string, errCode commands.StatusCode) {
	sw.log.Error(errMsg)
	// response.Data = nil
	response.ErrorMessage = errMsg
	response.ErrorStatus = errCode
}

func (iw *IssuerWorker) handleSignRequest(req *commands.SignRequest) *commands.Response {
	response := iw.getDefaultResponse()

	if len(req.PubM) > len(iw.sk.Y()) {
		errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports."+
			" Got: %v, expected at most: %v", len(req.PubM), len(iw.sk.Y()))
		iw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	bigs, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		iw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	sig, err := iw.SignWrapper(iw.sk, bigs)
	if err != nil {
		// TODO: should client really know those details?
		errMsg := fmt.Sprintf("Error while signing message: %v", err)
		iw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	iw.log.Debugf("Writing back signature")
	response.Data = sig
	return response
}

//nolint: unparam
func (iw *IssuerWorker) handleVerificationKeyRequest(req *commands.VerificationKeyRequest) *commands.Response {
	response := iw.getDefaultResponse()
	response.Data = iw.vk
	return response
}

func (iw *IssuerWorker) handleBlindSignRequest(req *commands.BlindSignRequest) *commands.Response {
	response := iw.getDefaultResponse()

	lambda := &coconut.Lambda{}
	if err := lambda.FromProto(req.Lambda); err != nil {
		errMsg := "Could not recover received lambda."
		iw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	if len(req.PubM)+len(lambda.Enc()) > len(iw.sk.Y()) {
		errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports."+
			" Got: %v, expected at most: %v", len(req.PubM)+len(lambda.Enc()), len(iw.sk.Y()))
		iw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	egPub := &elgamal.PublicKey{}
	if err := egPub.FromProto(req.EgPub); err != nil {
		errMsg := "Could not recover received ElGamal Public Key."
		iw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	bigs, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		iw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	sig, err := iw.BlindSignWrapper(iw.sk, lambda, egPub, bigs)
	if err != nil {
		// TODO: should client really know those details?
		errMsg := fmt.Sprintf("Error while signing message: %v", err)
		iw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	iw.log.Debugf("Writing back blinded signature")
	response.Data = sig
	return response
}

func (iw *IssuerWorker) handleLookUpCredentialRequest(req *commands.LookUpCredentialRequest) *commands.Response {
	response := iw.getDefaultResponse()
	current := iw.store.GetHighest()
	if current < req.Height {
		errMsg := fmt.Sprintf("Target height hasn't been processed yet. Target: %v, current: %v", req.Height, current)
		iw.setErrorResponse(response, errMsg, commands.StatusCode_NOT_PROCESSED_YET)
		return response
	}

	credPair := iw.store.GetCredential(req.Height, req.Gamma)
	if len(credPair.Credential) == 0 {
		errMsg := "Could not lookup the credential using provided arguments"
		iw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	response.Data = credPair
	return response
}

func (iw *IssuerWorker) handleLookUpBlockCredentialsRequest(req *commands.LookUpBlockCredentialsRequest,
) *commands.Response {
	response := iw.getDefaultResponse()
	current := iw.store.GetHighest()
	if current < req.Height {
		errMsg := fmt.Sprintf("Target height hasn't been processed yet. Target: %v, current: %v", req.Height, current)
		iw.setErrorResponse(response, errMsg, commands.StatusCode_NOT_PROCESSED_YET)
		return response
	}

	credPairs := iw.store.GetBlockCredentials(req.Height)
	if len(credPairs) == 0 {
		errMsg := "Could not lookup the credential using provided arguments. " +
			"Either there were no valid txs in this block or it wasn't processed yet."
		iw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	response.Data = credPairs
	return response
}

func (iw *IssuerWorker) worker() {
	for {
		select {
		case <-iw.HaltCh():
			iw.log.Noticef("Halting Coconut Issuer worker %d\n", iw.id)
			return
		case cmdReq := <-iw.incomingCh:
			cmd := cmdReq.Cmd()
			var response *commands.Response

			switch req := cmd.(type) {
			case *commands.SignRequest:
				iw.log.Notice("Received Sign (NOT blind) command")
				response = iw.handleSignRequest(req)

			case *commands.VerificationKeyRequest:
				iw.log.Notice("Received Get Verification Key command")
				response = iw.handleVerificationKeyRequest(req)

			case *commands.BlindSignRequest:
				iw.log.Notice("Received Blind Sign command")
				response = iw.handleBlindSignRequest(req)

			case *commands.LookUpCredentialRequest:
				iw.log.Notice("Received Look Up Credential Command")
				response = iw.handleLookUpCredentialRequest(req)

			case *commands.LookUpBlockCredentialsRequest:
				iw.log.Notice("Received Look Up Block Credentials Command")
				response = iw.handleLookUpBlockCredentialsRequest(req)

			default:
				errMsg := "Received Invalid Command"
				iw.log.Warning(errMsg)
				response = iw.getDefaultResponse()
				response.ErrorStatus = commands.StatusCode_INVALID_COMMAND
			}
			cmdReq.RetCh() <- response
		}
	}
}

func (pw *ProviderWorker) handleVerifyRequest(req *commands.VerifyRequest) *commands.Response {
	response := pw.getDefaultResponse()

	if pw.avk == nil {
		errMsg := providerStartupErr
		pw.setErrorResponse(response, errMsg, commands.StatusCode_UNAVAILABLE)
		return response
	}
	sig := &coconut.Signature{}
	if err := sig.FromProto(req.Sig); err != nil {
		errMsg := "Could not recover received signature."
		pw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	bigs, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		pw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	response.Data = pw.VerifyWrapper(pw.avk, bigs, sig)
	return response
}

func (pw *ProviderWorker) handleBlindVerifyRequest(req *commands.BlindVerifyRequest) *commands.Response {
	response := pw.getDefaultResponse()

	if pw.avk == nil {
		errMsg := providerStartupErr
		pw.setErrorResponse(response, errMsg, commands.StatusCode_UNAVAILABLE)
		return response
	}
	sig := &coconut.Signature{}
	if err := sig.FromProto(req.Sig); err != nil {
		errMsg := "Could not recover received signature."
		pw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	theta := &coconut.Theta{}
	if err := theta.FromProto(req.Theta); err != nil {
		errMsg := "Could not recover received theta."
		pw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	bigs, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		pw.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	response.Data = pw.BlindVerifyWrapper(pw.avk, sig, theta, bigs)
	return response
}

func (pw *ProviderWorker) handleSpendCredentialRequest(req *commands.SpendCredentialRequest) *commands.Response {
	response := pw.getDefaultResponse()
	response.Data = false

	pw.log.Warning("REQUIRES RE-IMPLEMENTATION")
	return response

	// // theoretically provider does not need to do any checks as if the request is invalid the blockchain will reject it,
	// // but we check if the user says it bound it to our address
	// address := req.MerchantAddress

	// if !bytes.Equal(address, sw.nymAccount.PublicKey) {
	// 	// check if perhaps our address is in uncompressed form but client bound it to the compressed version
	// 	var accountCompressed account.ECPublicKey = make([]byte, len(sw.nymAccount.PublicKey))
	// 	copy(accountCompressed, sw.nymAccount.PublicKey)
	// 	if err := accountCompressed.Compress(); err != nil {
	// 		sw.log.Critical("Couldn't compress our own account key")
	// 		// TODO: how to handle it?
	// 	}

	// 	if !bytes.Equal(address, accountCompressed) {
	// 		b64Addr := base64.StdEncoding.EncodeToString(accountCompressed)
	// 		b64Bind := base64.StdEncoding.EncodeToString(address)
	// 		errMsg := fmt.Sprintf("Request is bound to an invalid address, Expected: %v, actual: %v", b64Addr, b64Bind)
	// 		sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_BINDING)
	// 		return response
	// 	}
	// }

	// blockchainRequest, err := transaction.CreateNewDepositCoconutCredentialRequest(
	// 	req.Sig,
	// 	req.PubM,
	// 	req.Theta,
	// 	req.Value,
	// 	req.MerchantAddress,
	// )
	// if err != nil {
	// 	errMsg := fmt.Sprintf("Failed to create blockchain request: %v", err)
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
	// 	return response
	// }

	// blockchainResponse, err := sw.nymClient.Broadcast(blockchainRequest)
	// if err != nil {
	// 	errMsg := fmt.Sprintf("Failed to send transaction to the blockchain: %v", err)
	// 	sw.log.Critical(errMsg)
	// 	response.ErrorMessage = errMsg
	// 	response.ErrorStatus = commands.StatusCode_PROCESSING_ERROR
	// 	return response
	// }

	// sw.log.Notice("Received response from the blockchain. Return code: %v; Additional Data: %v",
	// 	code.ToString(blockchainResponse.DeliverTx.Code), string(blockchainResponse.DeliverTx.Data))

	// if blockchainResponse.DeliverTx.Code != code.OK {
	// 	errMsg := fmt.Sprintf("The transaction failed to be included on the blockchain. Errorcode: %v - %v",
	// 		blockchainResponse.DeliverTx.Code, code.ToString(blockchainResponse.DeliverTx.Code))
	// 	sw.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_TRANSACTION)
	// 	return response
	// }

	// // the response data in future might be provider dependent, to include say some authorization token
	// response.ErrorStatus = commands.StatusCode_OK
	// response.Data = true
	// return response
}

func (pw *ProviderWorker) worker() {
	for {
		select {
		case <-pw.HaltCh():
			pw.log.Noticef("Halting Coconut Provider worker %d\n", pw.id)
			return
		case cmdReq := <-pw.incomingCh:
			cmd := cmdReq.Cmd()
			var response *commands.Response

			switch req := cmd.(type) {
			case *commands.VerifyRequest:
				pw.log.Notice("Received Verify (NOT blind) command")
				response = pw.handleVerifyRequest(req)

			case *commands.BlindVerifyRequest:
				pw.log.Notice("Received Blind Verify Command")
				response = pw.handleBlindVerifyRequest(req)

			case *commands.SpendCredentialRequest:
				pw.log.Notice("Received Spend Credential Command")
				response = pw.handleSpendCredentialRequest(req)

			default:
				errMsg := "Received Invalid Command"
				pw.log.Warning(errMsg)
				response = pw.getDefaultResponse()
				response.ErrorStatus = commands.StatusCode_INVALID_COMMAND
			}
			cmdReq.RetCh() <- response
		}
	}
}

// Config encapsulates arguments passed in New to create new instance of the serverworker.
type Config struct {
	ID         uint64
	Params     *coconut.Params
	JobQueue   chan<- *jobpacket.JobPacket
	IncomingCh <-chan *commands.CommandRequest
	Log        *logger.Logger
	NymClient  *nymclient.Client
	Store      *storage.Database
}

// New creates new instance of a serverWorker.
func NewBaseWorker(cfg *Config) (*ServerWorker, error) {
	sw := &ServerWorker{
		CoconutWorker: coconutworker.New(cfg.JobQueue, cfg.Params),
		incomingCh:    cfg.IncomingCh,
		id:            cfg.ID,
		nymClient:     cfg.NymClient,
		store:         cfg.Store,
		log:           cfg.Log.GetLogger(fmt.Sprintf("Serverworker:%d", int(cfg.ID))),
	}

	return sw, nil
}

func NewIssuerWorker(baseConfig *Config,
	iaid uint32,
	sk *coconut.SecretKey,
	vk *coconut.VerificationKey,
) (*IssuerWorker, error) {

	baseWorker, err := NewBaseWorker(baseConfig)
	if err != nil {
		return nil, err
	}
	iw := &IssuerWorker{
		ServerWorker: baseWorker,
		iaid:         iaid,
		sk:           sk,
		vk:           vk,
	}
	iw.Go(iw.worker)

	return iw, nil

}

func NewProviderWorker(baseConfig *Config, avk *coconut.VerificationKey) (*ProviderWorker, error) {
	baseWorker, err := NewBaseWorker(baseConfig)
	if err != nil {
		return nil, err
	}

	pw := &ProviderWorker{
		ServerWorker: baseWorker,
		avk:          avk,
	}
	pw.Go(pw.worker)

	return pw, nil
}
