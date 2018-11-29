// cryptoworker.go - Coconut Worker for Coconut server.
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

// todo: description
package cryptoworker

import (
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"gopkg.in/op/go-logging.v1"

	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/server/commands"
)

// Worker allows writing coconut actions to a shared job queue,
// so that they could be run concurrently.
type Worker struct {
	worker.Worker
	cw *coconutworker.Worker

	incomingCh <-chan interface{}
	log        *logging.Logger

	sk *coconut.SecretKey // ensure they can be safely shared between multiple workers
	vk *coconut.VerificationKey

	avk *coconut.VerificationKey // only used if server is a provider

	id uint64
}

func (w *Worker) CoconutWorker() *coconutworker.Worker {
	return w.cw
}

func (w *Worker) setErrorResponse(response *commands.Response, errMsg string, errCode commands.StatusCode) {
	w.log.Error(errMsg)
	response.Data = nil
	response.ErrorMessage = errMsg
	response.ErrorStatus = errCode
}

// todo: clean up in next iteration, error handling is way too messy right now
func (w *Worker) worker() {
	for {
		var cmdReq *commands.CommandRequest
		select {
		case <-w.HaltCh():
			w.log.Debugf("Halting Coconut Server worker %d\n", w.id)
			return
		case e := <-w.incomingCh:
			cmdReq = e.(*commands.CommandRequest)
			cmd := cmdReq.Cmd()
			response := &commands.Response{
				Data:         nil,
				ErrorStatus:  commands.StatusCode_UNKNOWN,
				ErrorMessage: "",
			}

			switch v := cmd.(type) {
			case *commands.SignRequest:
				w.log.Notice("Received Sign (NOT blind) command")
				if len(v.PubM) > len(w.sk.Y()) {
					errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports. Got: %v, expected at most: %v", len(v.PubM), len(w.sk.Y()))
					w.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
					continue
				}
				sig, err := w.cw.SignWrapper(w.sk, coconut.BigSliceFromProto(v.PubM))
				if err != nil {
					// todo: should client really know those details?
					errMsg := fmt.Sprintf("Error while signing message: %v", err)
					w.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
					continue
				}
				w.log.Debugf("Writing back signature")
				response.Data = sig
			case *commands.VerificationKeyRequest:
				w.log.Notice("Received Get Verification Key command")
				response.Data = w.vk
			case *commands.VerifyRequest:
				w.log.Notice("Received Verify (NOT blind) command")
				if w.avk != nil {
					sig := &coconut.Signature{}
					if err := sig.FromProto(v.Sig); err != nil {
						errMsg := "Could not recover received signature."
						w.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
						continue
					}
					response.Data = w.cw.VerifyWrapper(w.avk, coconut.BigSliceFromProto(v.PubM), sig)
				} else {
					errMsg := "The aggregate verification key is nil. Is the server a provider? And if so, has it completed the start up sequence?"
					w.setErrorResponse(response, errMsg, commands.StatusCode_UNAVAILABLE)
				}
			case *commands.BlindSignRequest:
				w.log.Notice("Received Blind Sign command")
				bsm := &coconut.BlindSignMats{}
				if err := bsm.FromProto(v.BlindSignMats); err != nil {
					errMsg := "Could not recover received blindSignMats."
					w.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
				}
				if len(v.PubM)+len(bsm.Enc()) > len(w.sk.Y()) {
					errMsg := fmt.Sprintf("Received more attributes to sign than what the server supports. Got: %v, expected at most: %v", len(v.PubM)+len(bsm.Enc()), len(w.sk.Y()))
					w.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
					continue
				}
				egPub := &elgamal.PublicKey{}
				if err := egPub.FromProto(v.EgPub); err != nil {
					errMsg := "Could not recover received blindSignMats."
					w.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
					break
				}
				sig, err := w.cw.BlindSignWrapper(w.sk, bsm, egPub, coconut.BigSliceFromProto(v.PubM))
				if err != nil {
					// todo: should client really know those details?
					errMsg := fmt.Sprintf("Error while signing message: %v", err)
					w.setErrorResponse(response, errMsg, commands.StatusCode_PROCESSING_ERROR)
					continue
				}
				w.log.Debugf("Writing back blinded signature")
				response.Data = sig
			case *commands.BlindVerifyRequest:
				w.log.Notice("Received Blind Verify Command")
				if w.avk != nil {
					sig := &coconut.Signature{}
					if err := sig.FromProto(v.Sig); err != nil {
						errMsg := "Could not recover received signature."
						w.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
						break
					}
					bsm := &coconut.BlindShowMats{}
					if err := bsm.FromProto(v.BlindShowMats); err != nil {
						errMsg := "Could not recover received blindSignMats."
						w.setErrorResponse(response, errMsg, commands.StatusCode_INVALID_ARGUMENTS)
						break
					}
					response.Data = w.cw.BlindVerifyWrapper(w.avk, sig, bsm, coconut.BigSliceFromProto(v.PubM))
				} else {
					errMsg := "The aggregate verification key is nil. Is the server a provider? And if so, has it completed the start up sequence?"
					w.setErrorResponse(response, errMsg, commands.StatusCode_UNAVAILABLE)
				}
			default:
				errMsg := "Received Invalid Command"
				w.log.Critical(errMsg)
				response.ErrorStatus = commands.StatusCode_INVALID_COMMAND
			}

			cmdReq.RetCh() <- response
		}
	}
}

// New creates new instance of a coconutWorker.
// todo: simplify attributes...
// nolint: lll
func New(jobQueue chan<- interface{}, incomingCh <-chan interface{}, id uint64, l *logger.Logger, params *coconut.Params, sk *coconut.SecretKey, vk *coconut.VerificationKey, avk *coconut.VerificationKey) *Worker {
	cw := coconutworker.New(jobQueue, params)

	w := &Worker{
		cw:         cw,
		incomingCh: incomingCh,
		id:         id,
		sk:         sk,
		vk:         vk,
		avk:        avk,
		log:        l.GetLogger(fmt.Sprintf("Servercryptoworker:%d", int(id))),
	}

	w.Go(w.worker)
	return w
}

// func init with q to make params
