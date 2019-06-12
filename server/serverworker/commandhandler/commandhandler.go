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
	"bytes"
	"context"
	"fmt"
	"reflect"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/query"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/server/issuer/utils"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	nymclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	ethcommon "github.com/ethereum/go-ethereum/common"
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
	pubM, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Error while recovering big numbers from the slice: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}
	response.Data = reqData.CoconutWorker().BlindVerifyWrapper(avk, sig, theta, pubM)
	return response
}

type SpendCredentialVerificationData struct {
	Avk       *coconut.VerificationKey
	Address   ethcommon.Address
	NymClient *nymclient.Client // in theory it should be safe to use the same instance for multiple requests
}

type SpendCredentialRequestHandlerData struct {
	Cmd              *commands.SpendCredentialRequest
	Worker           *coconutworker.CoconutWorker
	Logger           *logging.Logger
	VerificationData SpendCredentialVerificationData
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
	return handlerData.VerificationData
}

func SpendCredentialRequestHandler(ctx context.Context, reqData HandlerData) *commands.Response {
	req := reqData.Command().(*commands.SpendCredentialRequest)
	verificationData := reqData.Data().(SpendCredentialVerificationData)
	log := reqData.Log()
	response := DefaultResponse()
	response.Data = false

	log.Debug("SpendCredentialRequestHandler")

	if !bytes.Equal(req.MerchantAddress, verificationData.Address[:]) {
		errMsg := "Invalid merchant address"
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_BINDING)
		return response
	}

	sig := &coconut.Signature{}
	if err := sig.FromProto(req.Sig); err != nil {
		errMsg := fmt.Sprintf("Failed to unmarshal signature: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_SIGNATURE)
		return response
	}

	thetaTumbler := &coconut.ThetaTumbler{}
	if err := thetaTumbler.FromProto(req.Theta); err != nil {
		errMsg := fmt.Sprintf("Failed to unmarshal theta: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	pubM, err := coconut.BigSliceFromByteSlices(req.PubM)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to unmarshal public attributes: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	// Depends on provider settings, if we are to verify credential, we do just that (it includes checking the binding)
	// otherwise we only verify the binding
	// When the provider is going to redeem the credential for itself, it will be verified by the nym system anyway.
	if verificationData.Avk != nil {
		isValid := reqData.CoconutWorker().BlindVerifyTumblerWrapper(
			verificationData.Avk,
			sig,
			thetaTumbler,
			pubM,
			verificationData.Address[:],
		)
		if !isValid {
			setErrorResponse(log, response, "Failed to verify the data", commands.StatusCode_INVALID_SIGNATURE)
			return response
		}
		log.Info("The received data is valid")
	} else {
		bind, bindErr := coconut.CreateBinding(verificationData.Address[:])
		if bindErr != nil {
			log.Critical("Failed to create binding out of our own address")
			setErrorResponse(log, response, "Critical failure when generating own binding", commands.StatusCode_PROCESSING_ERROR)
			return response
		}
		if !bind.Equals(thetaTumbler.Zeta()) {
			setErrorResponse(log, response, "Invalid binding provided", commands.StatusCode_INVALID_BINDING)
			return response
		}
	}

	// this is not by any means a reliable check as this request is not properly ordered, etc.
	// All it does is check against credentials spent in the past (so say it would fail if client sent same request
	// to two SPs now)
	wasSpentRes, err := verificationData.NymClient.Query(query.ZetaStatus, req.Theta.Zeta)
	if err != nil {
		errMsg := "Failed to preliminarily check status of zeta"
		setErrorResponse(log, response, errMsg, commands.StatusCode_UNAVAILABLE)
		return response
	}

	if bytes.Equal(wasSpentRes.Response.Value, []byte{1}) {
		errMsg := "Received zeta was already spent before"
		setErrorResponse(log, response, errMsg, commands.StatusCode_DOUBLE_SPENDING_ATTEMPT)
	}

	log.Debug("The received zeta seems to not have been spent before (THIS IS NOT A GUARANTEE)")

	// TODO: now it's a question of whether we want to immediately try to deposit our credential or wait and do it later
	// and possibly in bulk. In the former case: store the data in the database
	// However, for the demo sake (since it's easier), deposit immediately
	// TODO: in future we could just store that marshalled request (as below) rather than all attributes separately
	log.Debug("Going to deposit the received credential")
	blockchainRequest, err := transaction.CreateNewDepositCoconutCredentialRequest(
		req.Sig,
		req.PubM,
		req.Theta,
		req.Value,
		verificationData.Address,
	)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to create blockchain request: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
		return response
	}

	blockchainResponse, err := verificationData.NymClient.Broadcast(blockchainRequest)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to send transaction to the blockchain: %v", err)
		setErrorResponse(log, response, errMsg, commands.StatusCode_PROCESSING_ERROR)
		return response
	}

	log.Debugf("Received response from the blockchain. Return code: %v; Additional Data: %v",
		code.ToString(blockchainResponse.DeliverTx.Code), string(blockchainResponse.DeliverTx.Data))

	if blockchainResponse.DeliverTx.Code != code.OK {
		errMsg := fmt.Sprintf("The transaction failed to be included on the blockchain. Errorcode: %v - %v",
			blockchainResponse.DeliverTx.Code, code.ToString(blockchainResponse.DeliverTx.Code))
		setErrorResponse(log, response, errMsg, commands.StatusCode_INVALID_TRANSACTION)
		return response
	}

	// the response data in future might be provider dependent, to include say some authorization token
	response.ErrorStatus = commands.StatusCode_OK
	response.Data = true
	return response
}
