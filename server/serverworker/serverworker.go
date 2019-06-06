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
	"errors"
	"fmt"
	"reflect"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobpacket"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/serverworker/commandhandler"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	nymclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"gopkg.in/op/go-logging.v1"
)

/// ServerWorker allows writing coconut actions to a shared job queue,
// so that they could be run concurrently.
type ServerWorker struct {
	worker.Worker
	IssuerWorker
	ProviderWorker
	*coconutworker.CoconutWorker // TODO: since CoconutWorker does not have many attributes should we still use reference?
	handlers                     commandhandler.HandlerRegistry
	incomingCh                   <-chan *commands.CommandRequest
	log                          *logging.Logger
	nymClient                    *nymclient.Client
	store                        *storage.Database
	id                           uint64
}

type IssuerWorker struct {
	tsk *coconut.ThresholdSecretKey
	tvk *coconut.ThresholdVerificationKey
}

type ProviderWorker struct {
	avk *coconut.VerificationKey
}

func (sw *ServerWorker) RegisterAsIssuer(tsk *coconut.ThresholdSecretKey, tvk *coconut.ThresholdVerificationKey) error {
	sw.log.Noticef("Registering ServerWorker%v as Issuer", sw.id)
	if !coconut.ValidateKeyPair(tsk.SecretKey, tvk.VerificationKey) {
		sw.log.Error("Invalid keypair provided")
		return errors.New("invalid keypair provided")
	}
	sw.IssuerWorker = IssuerWorker{
		tsk: tsk,
		tvk: tvk,
	}
	// TODO: is there a better alternative for the way handlers are registered now?
	sw.RegisterHandler(&commands.SignRequest{},
		commandhandler.SignRequestHandler,
		func(cmd commands.Command) commandhandler.HandlerData {
			return &commandhandler.SignRequestHandlerData{
				Cmd:       cmd.(*commands.SignRequest),
				Worker:    sw.CoconutWorker,
				Logger:    sw.log,
				SecretKey: sw.tsk,
			}
		})
	sw.RegisterHandler(&commands.BlindSignRequest{},
		commandhandler.BlindSignRequestHandler,
		func(cmd commands.Command) commandhandler.HandlerData {
			return &commandhandler.BlindSignRequestHandlerData{
				Cmd:       cmd.(*commands.BlindSignRequest),
				Worker:    sw.CoconutWorker,
				Logger:    sw.log,
				SecretKey: sw.tsk,
			}
		})
	sw.RegisterHandler(&commands.VerificationKeyRequest{},
		commandhandler.VerificationKeyRequestHandler,
		func(cmd commands.Command) commandhandler.HandlerData {
			return &commandhandler.VerificationKeyRequestHandlerData{
				Cmd:             cmd.(*commands.VerificationKeyRequest),
				Worker:          sw.CoconutWorker,
				Logger:          sw.log,
				VerificationKey: sw.tvk,
			}
		})
	sw.RegisterHandler(&commands.LookUpCredentialRequest{},
		commandhandler.LookUpCredentialRequestHandler,
		func(cmd commands.Command) commandhandler.HandlerData {
			return &commandhandler.LookUpCredentialRequestHandlerData{
				Cmd:    cmd.(*commands.LookUpCredentialRequest),
				Worker: sw.CoconutWorker,
				Logger: sw.log,
				Store:  sw.store,
			}
		})
	sw.RegisterHandler(&commands.LookUpBlockCredentialsRequest{},
		commandhandler.LookUpBlockCredentialsRequestHandler,
		func(cmd commands.Command) commandhandler.HandlerData {
			return &commandhandler.LookUpBlockCredentialsRequestHandlerData{
				Cmd:    cmd.(*commands.LookUpBlockCredentialsRequest),
				Worker: sw.CoconutWorker,
				Logger: sw.log,
				Store:  sw.store,
			}
		})

	return nil
}

func (sw *ServerWorker) RegisterAsProvider(avk *coconut.VerificationKey) error {
	sw.log.Noticef("Registering ServerWorker%v as Provider", sw.id)
	if !avk.Validate() {
		sw.log.Error("Invalid verification key provided")
		return errors.New("invalid verification key provided")
	}
	sw.ProviderWorker = ProviderWorker{
		avk: avk,
	}

	sw.RegisterHandler(&commands.VerifyRequest{},
		commandhandler.VerifyRequestHandler,
		func(cmd commands.Command) commandhandler.HandlerData {
			return &commandhandler.VerifyRequestHandlerData{
				Cmd:             cmd.(*commands.VerifyRequest),
				Worker:          sw.CoconutWorker,
				Logger:          sw.log,
				VerificationKey: sw.tvk.VerificationKey,
			}
		})
	sw.RegisterHandler(&commands.BlindVerifyRequest{},
		commandhandler.BlindVerifyRequestHandler,
		func(cmd commands.Command) commandhandler.HandlerData {
			return &commandhandler.BlindVerifyRequestHandlerData{
				Cmd:             cmd.(*commands.BlindVerifyRequest),
				Worker:          sw.CoconutWorker,
				Logger:          sw.log,
				VerificationKey: sw.tvk.VerificationKey,
			}
		})
	sw.RegisterHandler(&commands.SpendCredentialRequest{},
		commandhandler.SpendCredentialRequestHandler,
		func(cmd commands.Command) commandhandler.HandlerData {
			return &commandhandler.SpendCredentialRequestHandlerData{
				Cmd:    cmd.(*commands.SpendCredentialRequest),
				Worker: sw.CoconutWorker,
				Logger: sw.log,
				TODO:   nil,
			}
		})
	return nil
}

func (sw *ServerWorker) RegisterHandler(o interface{},
	hfn commandhandler.HandlerFunc,
	dfn func(commands.Command) commandhandler.HandlerData) {
	typ := reflect.TypeOf(o)
	if _, ok := sw.handlers[typ]; ok {
		sw.log.Warningf("%v already had a registered handler. It will be overritten", typ)
	}

	sw.log.Debugf("Registering handler for %v", typ)
	// TODO: perhaps move to commandhandler package?
	sw.handlers[typ] = commandhandler.HandlerRegistryEntry{
		Fn:     hfn,
		DataFn: dfn,
	}
}

func (sw *ServerWorker) worker() {
	for {
		select {
		case <-sw.HaltCh():
			sw.log.Noticef("Halting Coconut Serwer worker %d\n", sw.id)
			return
		case cmdReq := <-sw.incomingCh:
			cmd := cmdReq.Cmd()
			var response *commands.Response

			typ := reflect.TypeOf(cmd)
			sw.log.Debugf("Received command of type %v", typ)
			handler, ok := sw.handlers[typ]
			if !ok {
				errMsg := fmt.Sprintf("Received Invalid Command - no registered handler for %v", typ)
				sw.log.Warning(errMsg)
				response = commandhandler.DefaultResponse()
				response.ErrorStatus = commands.StatusCode_INVALID_COMMAND

				cmdReq.RetCh() <- response
				break
			}

			response = handler.Fn(cmdReq.Ctx(), handler.DataFn(cmd))
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
func New(cfg *Config) (*ServerWorker, error) {
	sw := &ServerWorker{
		CoconutWorker: coconutworker.New(cfg.JobQueue, cfg.Params),
		handlers:      make(commandhandler.HandlerRegistry),
		incomingCh:    cfg.IncomingCh,
		id:            cfg.ID,
		nymClient:     cfg.NymClient,
		store:         cfg.Store,
		log:           cfg.Log.GetLogger(fmt.Sprintf("Serverworker:%d", int(cfg.ID))),
	}

	sw.Go(sw.worker)
	return sw, nil
}
