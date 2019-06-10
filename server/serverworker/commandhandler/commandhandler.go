// commandhandler.go - handlers for coconut requests.
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

// Package commandhandler contains functions that are used to resolve commands issued to issuers and providers.
package commandhandler

import (
	"context"
	"fmt"
	"reflect"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/server/issuer/utils"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	"gopkg.in/op/go-logging.v1"
)

// TODO: perhaps if it's too expensive, replace reflect.Type with some string or even a byte?
type HandlerRegistry map[reflect.Type]HandlerRegistryEntry

type HandlerRegistryEntry struct {
	DataFn func(cmd commands.Command) HandlerData
	Fn     HandlerFunc
}

// context is really useful for the most time consuming functions like blindverify
// it is not very useful for say "getVerificatonKey", but nevertheless, it is there for both,
// completion sake and future proofness
type HandlerFunc func(context.Context, HandlerData) *commands.Response

// command - request to resolve
// logger - possibly to remove later?
// pointer to coconut worker - that deals with actual crypto (passes it down to workers etc)
// request specific piece of data - for sign it's the secret key, for verify it's the verification key, etc.
type HandlerData interface {
	Command() commands.Command
	CoconutWorker() *coconutworker.CoconutWorker
	Log() *logging.Logger
	Data() interface{}
}

func DefaultResponse() *commands.Response {
	return &commands.Response{
		Data:         nil,
		ErrorStatus:  commands.DefaultResponseErrorStatusCode,
		ErrorMessage: commands.DefaultResponseErrorMessage,
	}
}

func setErrorResponse(log *logging.Logger, response *commands.Response, errMsg string, errCode commands.StatusCode) {
	log.Error(errMsg)
	// response.Data = nil
	response.ErrorMessage = errMsg
	response.ErrorStatus = errCode
}

type SignRequestHandlerData struct {
	Cmd       *commands.SignRequest
	Worker    *coconutworker.CoconutWorker
	Logger    *logging.Logger
	SecretKey *coconut.ThresholdSecretKey
}

func (handlerData *SignRequestHandlerData) Command() commands.Command {
	return handlerData.Cmd
}

func (handlerData *SignRequestHandlerData) CoconutWorker() *coconutworker.CoconutWorker {
	return handlerData.Worker
}

func (handlerData *SignRequestHandlerData) Log() *logging.Logger {
	return handlerData.Logger
}

func (handlerData *SignRequestHandlerData) Data() interface{} {
	return handlerData.SecretKey
}

func SignRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	req := reqData.Command().(*commands.SignRequest)
	log := reqData.Log()
	tsk := reqData.Data().(*coconut.ThresholdSecretKey)
	response := DefaultResponse()

	log.Debug("SignRequestHandler")
	if len(req.PubM) > len(tsk.Y()) {
		errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports."+
			" Got: %v, expected at most: %v", len(req.PubM), len(tsk.Y()))
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	bigs, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	sig, err := reqData.CoconutWorker().SignWrapper(tsk.SecretKey, bigs)
	if err != nil {
		// TODO: should client really know those details?
		errMsg := fmt.Sprintf("Error while signing message: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	log.Debugf("Writing back signature %v", sig)
	response.Data = utils.IssuedSignature{
		Sig:      sig,
		IssuerID: tsk.ID(),
	}
	return response
}

type VerificationKeyRequestHandlerData struct {
	Cmd             *commands.VerificationKeyRequest
	Worker          *coconutworker.CoconutWorker
	Logger          *logging.Logger
	VerificationKey *coconut.ThresholdVerificationKey
}

func (handlerData *VerificationKeyRequestHandlerData) Command() commands.Command {
	return handlerData.Cmd
}

func (handlerData *VerificationKeyRequestHandlerData) CoconutWorker() *coconutworker.CoconutWorker {
	return handlerData.Worker
}

func (handlerData *VerificationKeyRequestHandlerData) Log() *logging.Logger {
	return handlerData.Logger
}

func (handlerData *VerificationKeyRequestHandlerData) Data() interface{} {
	return handlerData.VerificationKey
}

func VerificationKeyRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	response := DefaultResponse()
	log := reqData.Log()
	log.Debug("VerificationKeyRequestHandler")
	response.Data = reqData.Data()
	return response
}

type BlindSignRequestHandlerData struct {
	Cmd       *commands.BlindSignRequest
	Worker    *coconutworker.CoconutWorker
	Logger    *logging.Logger
	SecretKey *coconut.ThresholdSecretKey
}

func (handlerData *BlindSignRequestHandlerData) Command() commands.Command {
	return handlerData.Cmd
}

func (handlerData *BlindSignRequestHandlerData) CoconutWorker() *coconutworker.CoconutWorker {
	return handlerData.Worker
}

func (handlerData *BlindSignRequestHandlerData) Log() *logging.Logger {
	return handlerData.Logger
}

func (handlerData *BlindSignRequestHandlerData) Data() interface{} {
	return handlerData.SecretKey
}

func BlindSignRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	req := reqData.Command().(*commands.BlindSignRequest)
	log := reqData.Log()
	tsk := reqData.Data().(*coconut.ThresholdSecretKey)
	response := DefaultResponse()

	log.Debug("BlindSignRequestHandler")
	lambda := &coconut.Lambda{}
	if err := lambda.FromProto(req.Lambda); err != nil {
		errMsg := "Could not recover received lambda."
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	if len(req.PubM)+len(lambda.Enc()) > len(tsk.Y()) {
		errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports."+
			" Got: %v, expected at most: %v", len(req.PubM)+len(lambda.Enc()), len(tsk.Y()))
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	egPub := &elgamal.PublicKey{}
	if err := egPub.FromProto(req.EgPub); err != nil {
		errMsg := "Could not recover received ElGamal Public Key."
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	bigs, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	sig, err := reqData.CoconutWorker().BlindSignWrapper(tsk.SecretKey, lambda, egPub, bigs)
	if err != nil {
		// TODO: should client really know those details?
		errMsg := fmt.Sprintf("Error while signing message: %v", err)
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	log.Debugf("Writing back blinded signature")
	response.Data = utils.IssuedSignature{
		Sig:      sig,
		IssuerID: tsk.ID(),
	}
	return response
}

type LookUpCredentialRequestHandlerData struct {
	Cmd    *commands.LookUpCredentialRequest
	Worker *coconutworker.CoconutWorker
	Logger *logging.Logger
	Store  *storage.Database
}

func (handlerData *LookUpCredentialRequestHandlerData) Command() commands.Command {
	return handlerData.Cmd
}

func (handlerData *LookUpCredentialRequestHandlerData) CoconutWorker() *coconutworker.CoconutWorker {
	return handlerData.Worker
}

func (handlerData *LookUpCredentialRequestHandlerData) Log() *logging.Logger {
	return handlerData.Logger
}

func (handlerData *LookUpCredentialRequestHandlerData) Data() interface{} {
	return handlerData.Store
}

func LookUpCredentialRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	req := reqData.Command().(*commands.LookUpCredentialRequest)
	log := reqData.Log()
	store := reqData.Data().(*storage.Database)

	log.Debug("LookUpCredentialRequestHandler")
	response := DefaultResponse()
	current := store.GetHighest()
	if current < req.Height {
		errMsg := fmt.Sprintf("Target height hasn't been processed yet. Target: %v, current: %v", req.Height, current)
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_NOT_PROCESSED_YET)
		return response
	}

	credPair := store.GetCredential(req.Height, req.Gamma)
	if len(credPair.Credential.Sig) == 0 {
		errMsg := "Could not lookup the credential using provided arguments"
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	log.Debugf("Writing back credentials for height %v with gamma %v", req.Height, req.Gamma)
	response.Data = credPair
	return response
}

type LookUpBlockCredentialsRequestHandlerData struct {
	Cmd    *commands.LookUpBlockCredentialsRequest
	Worker *coconutworker.CoconutWorker
	Logger *logging.Logger
	Store  *storage.Database
}

func (handlerData *LookUpBlockCredentialsRequestHandlerData) Command() commands.Command {
	return handlerData.Cmd
}

func (handlerData *LookUpBlockCredentialsRequestHandlerData) CoconutWorker() *coconutworker.CoconutWorker {
	return handlerData.Worker
}

func (handlerData *LookUpBlockCredentialsRequestHandlerData) Log() *logging.Logger {
	return handlerData.Logger
}

func (handlerData *LookUpBlockCredentialsRequestHandlerData) Data() interface{} {
	return handlerData.Store
}

func LookUpBlockCredentialsRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	req := reqData.Command().(*commands.LookUpBlockCredentialsRequest)
	log := reqData.Log()
	store := reqData.Data().(*storage.Database)
	log.Debug("LookUpBlockCredentialsRequestHandler")

	response := DefaultResponse()
	current := store.GetHighest()
	if current < req.Height {
		errMsg := fmt.Sprintf("Target height hasn't been processed yet. Target: %v, current: %v", req.Height, current)
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_NOT_PROCESSED_YET)
		return response
	}

	credPairs := store.GetBlockCredentials(req.Height)
	if len(credPairs) == 0 {
		errMsg := "Could not lookup the credential using provided arguments. " +
			"Either there were no valid txs in this block or it wasn't processed yet."
		setErrorResponse(reqData.Log(), response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	log.Debugf("Writing back all credentials for height %v", req.Height)
	response.Data = credPairs
	return response
}

type VerifyRequestHandlerData struct {
	Cmd             *commands.VerifyRequest
	Worker          *coconutworker.CoconutWorker
	Logger          *logging.Logger
	VerificationKey *coconut.VerificationKey
}

func (handlerData *VerifyRequestHandlerData) Command() commands.Command {
	return handlerData.Cmd
}

func (handlerData *VerifyRequestHandlerData) CoconutWorker() *coconutworker.CoconutWorker {
	return handlerData.Worker
}

func (handlerData *VerifyRequestHandlerData) Log() *logging.Logger {
	return handlerData.Logger
}

func (handlerData *VerifyRequestHandlerData) Data() interface{} {
	return handlerData.VerificationKey
}

func VerifyRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	req := reqData.Command().(*commands.VerifyRequest)
	log := reqData.Log()
	response := DefaultResponse()
	avk := reqData.Data().(*coconut.VerificationKey)

	log.Debug("VerifyRequestHandler")
	sig := &coconut.Signature{}
	if err := sig.FromProto(req.Sig); err != nil {
		errMsg := "Could not recover received signature."
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	bigs, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	response.Data = reqData.CoconutWorker().VerifyWrapper(avk, bigs, sig)
	return response
}

type BlindVerifyRequestHandlerData struct {
	Cmd             *commands.BlindVerifyRequest
	Worker          *coconutworker.CoconutWorker
	Logger          *logging.Logger
	VerificationKey *coconut.VerificationKey
}

func (handlerData *BlindVerifyRequestHandlerData) Command() commands.Command {
	return handlerData.Cmd
}

func (handlerData *BlindVerifyRequestHandlerData) CoconutWorker() *coconutworker.CoconutWorker {
	return handlerData.Worker
}

func (handlerData *BlindVerifyRequestHandlerData) Log() *logging.Logger {
	return handlerData.Logger
}

func (handlerData *BlindVerifyRequestHandlerData) Data() interface{} {
	return handlerData.VerificationKey
}

func BlindVerifyRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	req := reqData.Command().(*commands.BlindVerifyRequest)
	log := reqData.Log()
	response := DefaultResponse()
	avk := reqData.Data().(*coconut.VerificationKey)

	log.Debug("BlindVerifyRequestHandler")
	sig := &coconut.Signature{}
	if err := sig.FromProto(req.Sig); err != nil {
		errMsg := "Could not recover received signature."
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	theta := &coconut.Theta{}
	if err := theta.FromProto(req.Theta); err != nil {
		errMsg := "Could not recover received theta."
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}
	bigs, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	response.Data = reqData.CoconutWorker().BlindVerifyWrapper(avk, sig, theta, bigs)
	return response
}

type SpendCredentialRequestHandlerData struct {
	Cmd    *commands.SpendCredentialRequest
	Worker *coconutworker.CoconutWorker
	Logger *logging.Logger
	TODO   interface{}
}

func (handlerData *SpendCredentialRequestHandlerData) Command() commands.Command {
	return handlerData.Cmd
}

func (handlerData *SpendCredentialRequestHandlerData) CoconutWorker() *coconutworker.CoconutWorker {
	return handlerData.Worker
}

func (handlerData *SpendCredentialRequestHandlerData) Log() *logging.Logger {
	return handlerData.Logger
}

func (handlerData *SpendCredentialRequestHandlerData) Data() interface{} {
	return handlerData.TODO
}

func SpendCredentialRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	req := reqData.Command().(*commands.SpendCredentialRequest)
	log := reqData.Log()
	response := DefaultResponse()
	response.Data = false

	log.Debug("SpendCredentialRequestHandler")
	_ = req

	log.Warning("REQUIRES RE-IMPLEMENTATION")
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
	// 		sw.setErrorResponse(log,response, errMsg, commands.StatusCode_INVALID_BINDING)
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
	// 	sw.setErrorResponse(log,response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
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
	// 	sw.setErrorResponse(log,response, errMsg, commands.StatusCode_INVALID_TRANSACTION)
	// 	return response
	// }

	// // the response data in future might be provider dependent, to include say some authorization token
	// response.ErrorStatus = commands.StatusCode_OK
	// response.Data = true
	// return response
}
