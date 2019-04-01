// monitor.go - Blockchain monitor.
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

// Package monitor implements the support for monitoring the state of the Tendermint Blockchain
// (later Ethereum I guess?) to sign all comitted requests.
package monitor

import (
	"context"
	"fmt"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/logger"
	tmclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	"gopkg.in/op/go-logging.v1"
)

const (
	maxInterval = time.Second * 10

	// todo: figure out if we want query per tx or per block
	chainQuery = "tm.event = 'NewBlock'"
	// chainQuery = "tm.event = 'Tx'"

)

// Monitor represents the Blockchain monitor
type Monitor struct {
	worker.Worker

	tmClient      *tmclient.Client
	subscriberStr string
	eventsCh      <-chan ctypes.ResultEvent
	haltCh        chan struct{}
	latestBlock   int64

	log *logging.Logger
}

func (m *Monitor) worker() {
	for {
		select {
		case e := <-m.eventsCh:
			m.log.Notice("Received", e)
			_ = e

		case <-time.After(maxInterval):
			m.log.Warning("Timeout")
			// unsub and resub
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

// HaltCh returns channel that upon writing anything to it (or more importantly closing it),
// will cause monitor to halt
func (m *Monitor) HaltCh() <-chan struct{} {
	return m.haltCh
}

// New creates a new monitor.
func New(l *logger.Logger, tmClient *tmclient.Client, id int) (*Monitor, error) {
	// read db with current state etc
	subscriberStr := fmt.Sprintf("monitor%v", id)
	log := l.GetLogger("Monitor")

	// in case we didn't shutdown cleanly last time
	if err := tmClient.UnsubscribeAll(context.Background(), subscriberStr); err != nil {
		log.Noticef("%v", err)
	}

	eventsCh, err := tmClient.Subscribe(context.Background(), subscriberStr, chainQuery)
	if err != nil {
		return nil, err
	}

	monitor := &Monitor{
		tmClient:      tmClient,
		log:           log,
		subscriberStr: subscriberStr,
		eventsCh:      eventsCh,
		haltCh:        make(chan struct{}),
	}

	monitor.Go(monitor.worker)
	return monitor, nil
}
