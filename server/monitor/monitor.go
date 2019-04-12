// monitor.go - Blockchain monitor.
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

// Package monitor implements the support for monitoring the state of the Tendermint Blockchain
// (later Ethereum I guess?) to sign all comitted requests.
package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	tmclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	cmn "github.com/tendermint/tendermint/libs/common"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	"github.com/tendermint/tendermint/types"
	"gopkg.in/op/go-logging.v1"
)

const (
	maxInterval = time.Second * 10
	// todo: figure out if we want query per tx or per block

	// txs for actual data, block header to know how many should have arrived
	// (needed if node died after sending only part of them)
	headersQuery = "tm.event = 'NewBlockHeader'"
	txsQuery     = "tm.event = 'Tx'"
)

// Monitor represents the Blockchain monitor
type Monitor struct {
	sync.Mutex
	worker.Worker
	store                      *storage.Database
	tmClient                   *tmclient.Client
	subscriberStr              string
	txsEventsCh                <-chan ctypes.ResultEvent
	headersEventsCh            <-chan ctypes.ResultEvent
	haltCh                     chan struct{}
	latestConsecutiveProcessed int64              // everything up to that point (including it) is already stored on disk
	processedBlocks            map[int64]struct{} // think of it as a set rather than a hashmap
	unprocessedBlocks          map[int64]*block

	log *logging.Logger
}

type block struct {
	sync.Mutex
	creationTime   time.Time // approximate creation time of the given struct, NOT the actual block on the chain
	height         int64
	NumTxs         int64
	receivedHeader bool
	beingProcessed bool

	Txs []*tx
}

func (b *block) isFull() bool {
	b.Lock()
	defer b.Unlock()

	if int64(len(b.Txs)) != b.NumTxs {
		return false
	}

	for i := range b.Txs {
		if b.Txs[i] == nil {
			return false
		}
	}
	return true
}

func (b *block) addTx(newTx *tx) {
	b.Lock()
	defer b.Unlock()

	if len(b.Txs) < int(newTx.index)+1 {
		newTxs := make([]*tx, newTx.index+1)
		for _, oldTx := range b.Txs {
			if oldTx != nil {
				newTxs[oldTx.index] = oldTx
			}
		}
		b.Txs = newTxs
	}
	b.Txs[newTx.index] = newTx
}

func startNewBlock(header types.Header) *block {
	return &block{
		creationTime:   time.Now(),
		height:         header.Height,
		NumTxs:         header.NumTxs,
		receivedHeader: true,
		Txs:            make([]*tx, int(header.NumTxs)),
	}
}

type tx struct {
	height int64
	index  uint32
	Code   uint32
	Tags   []cmn.KVPair
}

func startNewTx(txData types.EventDataTx) *tx {
	return &tx{
		height: txData.Height,
		index:  txData.Index,
		Code:   txData.Result.Code,
		Tags:   txData.Result.Tags,
	}
}

// FinalizeHeight gets called when all txs from a particular block are processed.
func (m *Monitor) FinalizeHeight(height int64) {
	m.log.Debugf("Finalizing height %v", height)
	m.Lock()
	defer m.Unlock()
	if height == m.latestConsecutiveProcessed+1 {
		m.latestConsecutiveProcessed = height
		for i := height + 1; ; {
			if _, ok := m.processedBlocks[i]; ok {
				m.latestConsecutiveProcessed = i
				delete(m.processedBlocks, i)
			} else {
				break
			}
		}
		m.store.FinalizeHeight(m.latestConsecutiveProcessed)
	} else {
		m.processedBlocks[height] = struct{}{}
	}
	delete(m.unprocessedBlocks, height)
}

// GetLowestFullUnprocessedBlock returns block on lowest height that is currently not being processed.
func (m *Monitor) GetLowestFullUnprocessedBlock() (int64, *block) {
	m.Lock()
	defer m.Unlock()
	for k, v := range m.unprocessedBlocks {
		if v.isFull() && !v.beingProcessed { // allows for multiple processors
			return k, v
		}
		m.log.Errorf("Nope %v", k)
	}
	return -1, nil
}

func (m *Monitor) addNewBlock(b *block) {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.unprocessedBlocks[b.height]; !ok {
		m.unprocessedBlocks[b.height] = b
		return
	}

	m.log.Infof("Block at height: %v already present", b.height)
	if m.unprocessedBlocks[b.height].receivedHeader {
		// that's really an undefined behaviour. we probably received the same header twice?
		// ignore for now
	} else {
		oldTxs := m.unprocessedBlocks[b.height].Txs
		for _, oldTx := range oldTxs {
			if oldTx != nil {
				b.Txs[oldTx.index] = oldTx
			}
		}
		m.unprocessedBlocks[b.height] = b
	}
}

func (m *Monitor) addNewTx(newTx *tx) {
	m.Lock()
	defer m.Unlock()
	b, ok := m.unprocessedBlocks[newTx.height]
	if !ok {
		// we haven't received block header  and this is the first tx we received for that block
		tempBlock := &block{
			creationTime:   time.Now(),
			height:         newTx.height,
			NumTxs:         -1,
			receivedHeader: false,
			Txs:            make([]*tx, int(newTx.index)+1), // we know that there are at least that many txs in the block
		}
		tempBlock.Txs[newTx.index] = newTx
		m.unprocessedBlocks[newTx.height] = tempBlock
		return
	}
	b.addTx(newTx)
}

// for now assume we receive all subscription events and nodes never go down
func (m *Monitor) worker() {
	for {
		select {
		case e := <-m.headersEventsCh:
			headerData := e.Data.(types.EventDataNewBlockHeader).Header

			m.log.Noticef("Received header for height : %v", headerData.Height)
			m.addNewBlock(startNewBlock(headerData))

		case e := <-m.txsEventsCh:
			txData := e.Data.(types.EventDataTx)

			m.log.Noticef("Received tx %v height: %v", txData.Index, txData.Height)
			m.addNewTx(startNewTx(txData))

		case <-time.After(maxInterval):
			m.log.Warning("Timeout")
			// unsub and resub + catchup
		case <-m.haltCh:
			return
		}
	}
}

// Halt stops the monitor and unsubscribes from any open queries.
func (m *Monitor) Halt() {
	m.log.Debugf("Halting the monitor")
	close(m.haltCh)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := m.tmClient.UnsubscribeAll(ctx, m.subscriberStr); err != nil {
		m.log.Noticef("%v", err)
	}
	m.Worker.Halt()
}

// New creates a new monitor.
func New(l *logger.Logger, tmClient *tmclient.Client, store *storage.Database, id int) (*Monitor, error) {
	// read db with current state etc
	subscriberStr := fmt.Sprintf("monitor%v", id)
	log := l.GetLogger("Monitor")

	// in case we didn't shutdown cleanly last time
	if err := tmClient.UnsubscribeAll(context.Background(), subscriberStr); err != nil {
		log.Noticef("%v", err)
	}

	headersEventsCh, err := tmClient.Subscribe(context.Background(), subscriberStr, headersQuery)
	if err != nil {
		return nil, err
	}

	txsEventsCh, err := tmClient.Subscribe(context.Background(), subscriberStr, txsQuery)
	if err != nil {
		return nil, err
	}

	monitor := &Monitor{
		tmClient:          tmClient,
		store:             store,
		log:               log,
		subscriberStr:     subscriberStr,
		headersEventsCh:   headersEventsCh,
		txsEventsCh:       txsEventsCh,
		haltCh:            make(chan struct{}),
		unprocessedBlocks: make(map[int64]*block),
		processedBlocks:   make(map[int64]struct{}),
	}

	monitor.Go(monitor.worker)
	return monitor, nil
}
