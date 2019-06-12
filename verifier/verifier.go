// verifier.go - A Nym verifier
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

// Package verifier defines a Nym verifier responsible for verifying received coconut signatures.
package verifier

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	monitor "0xacab.org/jstuczyn/CoconutGo/common/tendermintmonitor"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobqueue"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/concurrency/jobworker"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/requestqueue"
	"0xacab.org/jstuczyn/CoconutGo/server/serverworker"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	nymclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	tmconst "0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/constants"
	"0xacab.org/jstuczyn/CoconutGo/verifier/config"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"github.com/ethereum/go-ethereum/crypto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"gopkg.in/op/go-logging.v1"
)

const (
	dbName          = "verifierStore"
	backoffDuration = time.Second * 10
)

type Verifier struct {
	cfg           *config.Config
	monitor       *monitor.Monitor
	store         *storage.Database
	serverWorkers []*serverworker.ServerWorker
	jobWorkers    []*jobworker.JobWorker
	cmdChIn       chan<- *commands.CommandRequest
	log           *logging.Logger
	worker.Worker
	haltedCh chan struct{}
	haltOnce sync.Once
}

// TODO: DUPLICATE CODE WITH provider.go!!
func checkDuplicateID(ids []*Curve.BIG, id *Curve.BIG) bool {
	for _, el := range ids {
		if el == nil {
			continue
		}
		if Curve.Comp(el, id) == 0 {
			return true
		}
	}
	return false
}

// TODO: DUPLICATE CODE WITH provider.go!!
func (v *Verifier) loadAndAggregateVerificationKeys(files, addresses []string, threshold int) (*coconut.VerificationKey, error) {
	if len(files) == 0 {
		if len(addresses) == 0 {
			v.log.Error("No files or addresses specified")
			return nil, errors.New("no files or addresses specified")
		}

		// TODO: reimplement that
		return nil, errors.New("can't query IAs yet")
	}

	if len(files) < threshold {
		return nil, errors.New("insufficient number of keys provided")
	}

	vks := make([]*coconut.VerificationKey, threshold)
	xs := make([]*Curve.BIG, threshold)

	for i, f := range files {
		// no point in parsing more than threshold number of them
		if i == threshold {
			break
		}

		tvk := &coconut.ThresholdVerificationKey{}
		if err := tvk.FromPEMFile(f); err != nil {
			return nil, fmt.Errorf("failed to load key from file %v: %v", f, err)
		}
		idBIG := Curve.NewBIGint(int(tvk.ID()))
		if checkDuplicateID(xs, idBIG) {
			return nil, fmt.Errorf("at least two keys have the same id: %v", tvk.ID())
		}

		vks[i] = tvk.VerificationKey
		xs[i] = idBIG
	}

	// we have already started serverworkers, they're just not registered as verifier yet,
	// but can perform crypto operations
	avk := v.serverWorkers[0].AggregateVerificationKeysWrapper(vks, coconut.NewPP(xs))

	return avk, nil
}

func (v *Verifier) worker() {
	for {
		select {
		case <-v.HaltCh():
			v.log.Debug("Returning from initial select")
			return
		default:
			v.log.Debug("Default")
		}

		height, nextBlock := v.monitor.GetLowestFullUnprocessedBlock()
		if nextBlock == nil {
			v.log.Info("No blocks to process")
			select {
			case <-v.HaltCh():
				v.log.Debug("Returning from backoff select")
				return
			case <-time.After(backoffDuration):
				v.log.Debug("time after")
			}
			continue
		}

		v.log.Debugf("Processing block at height: %v", height)

		// In principle there should be no need to use the lock here because the block shouldn't be touched anymore,
		// but better safe than sorry
		nextBlock.Lock()

		for i, tx := range nextBlock.Txs {
			if tx.Code != code.OK || len(tx.Tags) == 0 ||
				!bytes.HasPrefix(tx.Tags[0].Key, tmconst.RedeemTokensRequestKeyPrefix) {
				v.log.Infof("Tx %v at height %v is not a redeem tokens request", i, height)
				continue
			}

			// blindSignMaterials := &coconut.ProtoBlindSignMaterials{}

			// err := proto.Unmarshal(tx.Tags[0].Value, blindSignMaterials)
			// if err != nil {
			// 	v.log.Errorf("Error while unmarshalling tags: %v", err)
			// 	continue
			// }

			// cmd := &commands.BlindSignRequest{
			// 	Lambda: blindSignMaterials.Lambda,
			// 	EgPub:  blindSignMaterials.EgPub,
			// 	PubM:   blindSignMaterials.PubM,
			// }

			// // just reuse existing processing pipeline
			// resCh := make(chan *commands.Response, 1)
			// cmdReq := commands.NewCommandRequest(cmd, resCh)

			// v.incomingCh <- cmdReq
			// res := <-resCh

			// if res == nil || res.Data == nil {
			// 	v.log.Errorf("Failed to sign request at index: %v on height %v", i, height)
			// }
			// v.log.Infof("Signed tx %v on height %v", i, height)

			// issuedCred := res.Data.(utils.IssuedSignature)

			// v.store.StoreIssuedSignature(height, blindSignMaterials.EgPub.Gamma, issuedCred)
			// v.log.Infof("Stored sig for tx %v on height %v", i, height)
		}
		v.monitor.FinalizeHeight(height)
		nextBlock.Unlock()
	}
}

// Wait waits till the Verifier is terminated for any reason.
func (v *Verifier) Wait() {
	<-v.haltedCh
}

// Shutdown cleanly shuts down a given Verifier instance.
func (v *Verifier) Shutdown() {
	v.haltOnce.Do(func() { v.halt() })
}

// right now it's only using a single worker so all of this is redundant,
// but more future proof if we decided to include more workers
func (v *Verifier) halt() {
	v.log.Notice("Starting graceful shutdown.")
	v.Worker.Halt()

	if v.monitor != nil {
		v.log.Debugf("Stopping Tendermint monitor")
		v.monitor.Halt()
		v.monitor = nil
	}

	for i, w := range v.serverWorkers {
		if w != nil {
			w.Halt()
			v.serverWorkers[i] = nil
		}
	}

	for i, w := range v.jobWorkers {
		if w != nil {
			w.Halt()
			v.jobWorkers[i] = nil
		}
	}

	if v.store != nil {
		v.log.Debugf("Closing datastore")
		v.store.Close()
		v.store = nil
	}

	v.log.Notice("Shutdown complete.")

	close(v.haltedCh)
}

func New(cfg *config.Config) (*Verifier, error) {
	log, err := logger.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		return nil, fmt.Errorf("failed to create a logger: %v", err)
	}
	verifierLog := log.GetLogger("verifier")
	verifierLog.Noticef("Logging level set to %v", cfg.Logging.Level)

	privateKey, err := crypto.LoadECDSA(cfg.Verifier.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load watcher's key: %v", err)
	}

	jobCh := jobqueue.New()     // commands issued by coconutworkers, like do pairing, g1mul, etc
	cmdCh := requestqueue.New() // verification commands created after seeing blockchain transactions

	params, err := coconut.Setup(cfg.Verifier.MaximumAttributes)
	if err != nil {
		return nil, err
	}

	nymClient, err := nymclient.New(cfg.Verifier.BlockchainNodeAddresses, log)
	if err != nil {
		errStr := fmt.Sprintf("Failed to create a nymClient: %v", err)
		verifierLog.Error(errStr)
		return nil, errors.New(errStr)
	}

	jobworkers := make([]*jobworker.JobWorker, cfg.Debug.NumJobWorkers)
	for i := range jobworkers {
		jobworkers[i] = jobworker.New(jobCh.Out(), uint64(i+1), log)
	}
	verifierLog.Noticef("Started %v Job Worker(s)", cfg.Debug.NumJobWorkers)

	store, err := storage.New(dbName, cfg.Verifier.DataDir)
	if err != nil {
		verifierLog.Errorf("Failed to create a data store: %v", err)
		return nil, err
	}

	mon, err := monitor.New(log, nymClient, store, fmt.Sprintf("Verifier%v", cfg.Verifier.Identifier))
	if err != nil {
		verifierLog.Errorf("Failed to spawn blockchain monitor")
		return nil, err
	}

	serverWorkers := make([]*serverworker.ServerWorker, 0, cfg.Debug.NumServerWorkers)
	for i := 0; i < cfg.Debug.NumServerWorkers; i++ {
		serverWorkerCfg := &serverworker.Config{
			JobQueue:   jobCh.In(),
			IncomingCh: cmdCh.Out(),
			ID:         uint64(i + 1),
			Log:        log,
			Params:     params,
			NymClient:  nymClient,
			Store:      store,
		}
		serverWorker, nerr := serverworker.New(serverWorkerCfg)
		if nerr == nil {
			serverWorkers = append(serverWorkers, serverWorker)
		} else {
			verifierLog.Errorf("Error while starting up serverWorker%v: %v", i, nerr)
		}
	}

	v := &Verifier{
		cfg:           cfg,
		monitor:       mon,
		store:         store,
		serverWorkers: serverWorkers,
		jobWorkers:    jobworkers,
		cmdChIn:       cmdCh.In(),
		log:           verifierLog,
		haltedCh:      make(chan struct{}),
	}

	avk, err := v.loadAndAggregateVerificationKeys(cfg.Verifier.IAVerificationKeys,
		cfg.Verifier.IAAddresses,
		cfg.Verifier.Threshold,
	)
	if err != nil {
		return nil, err
	}

	for i, sw := range v.serverWorkers {
		if err := sw.RegisterAsVerifier(avk, privateKey); err != nil {
			verifierLog.Warningf("Failed to register serverWorker%v as provider: %v", i, err)
		}
	}

	verifierLog.Noticef("Started %v Server Worker(s)", cfg.Debug.NumServerWorkers)

	v.Go(v.worker)

	return v, nil
}
