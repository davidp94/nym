// client.go - blockchain application communication
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

// Package client simplifies communication with the blockchain application
package client

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/logger"
	cmn "github.com/tendermint/tendermint/libs/common"
	tmclient "github.com/tendermint/tendermint/rpc/client"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	"gopkg.in/op/go-logging.v1"
)

const (
	reconnectionValidityPeriod = time.Second * 10
)

type Client struct {
	log               *logging.Logger
	possibleAddresses []string
	tmclient          *tmclient.HTTP
	failedToReconnect bool
	lastReconnection  time.Time

	connLock sync.Mutex
	logLock  sync.Mutex

	stopOnce sync.Once
}

var (
	// ErrReconnectFailure indicates error due to inability to reconnect to any specified node.
	ErrReconnectFailure = errors.New("Could not reconnect to any node")
)

// Broadcast sends a transaction to specified blockchain nodes and waits until it is included on the chain.
func (c *Client) Broadcast(tx []byte) (*ctypes.ResultBroadcastTxCommit, error) {
	return c.tmclient.BroadcastTxCommit(tx)
}

// SendSync sends an sync transaction to specified blockchain node. Note that there is no guarantee the transaction
// suceeded, but it definitely passed CheckTx and was included in the mempool. However, it still
// might return an error at DeliverTx.
func (c *Client) SendSync(tx []byte) (*ctypes.ResultBroadcastTx, error) {
	return c.tmclient.BroadcastTxSync(tx)
}

// SendAsync sends an async transaction to specified blockchain node. Note that there is no guarantee the transaction
// was included on the chain (it might not have been even added to the mempool because it could have failed CheckTx)
func (c *Client) SendAsync(tx []byte) (*ctypes.ResultBroadcastTx, error) {
	return c.tmclient.BroadcastTxAsync(tx)
}

// Query sends a query to specified blockchain node at given path. Note that it just returns state information
// (that might be stale) and is NOT included in transactions.
func (c *Client) Query(path string, data cmn.HexBytes) (*ctypes.ResultABCIQuery, error) {
	c.logMsg("DEBUG", "Doing Query at path %v", path)
	var res *ctypes.ResultABCIQuery
	var err error
	if c.tmclient != nil && c.tmclient.IsRunning() {
		res, err = c.tmclient.ABCIQuery(path, data)
	} else { // reconnection is most likely already in progress
		err = errors.New("Invalid client - reconnection required")
	}
	// network error
	if err != nil {
		c.logMsg("DEBUG", "Network error while quering the ABCI")
		err := c.reconnect(false)
		if err != nil {
			// workers should decide how to handle it
			return nil, err
		}
		// repeat the query
		return c.Query(path, data)
	}
	c.logMsg("DEBUG", "Query call done")
	return res, err
}

func (c *Client) reconnect(forceTry bool) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	c.logMsg("NOTICE", "Trying to reconnect to any working blockchain node")

	if c.lastReconnection.Add(reconnectionValidityPeriod).UnixNano() > time.Now().UnixNano() {
		// somebody else already caused reconnection
		c.logMsg("DEBUG", "Another instance already reconnected")
		return nil
	}

	// so that we would not try connecting with all addresses as somebody else already tried and failed
	if !forceTry && c.failedToReconnect {
		return ErrReconnectFailure
	}

	// we could try to reconnect to existing one, hoping itd come back, but might as well connect to another node
	if c.tmclient != nil {
		c.tmclient.Stop()
		c.tmclient = nil
	}

	for _, address := range c.possibleAddresses {
		c.logMsg("DEBUG", "Trying to connect to: %v", address)
		httpClient := tmclient.NewHTTP(address, "/websocket")
		err := httpClient.Start()
		if err != nil {
			// can't connect to that node
			c.logMsg("ERROR", "Could not connect to: %v (%v)", address, err)
			continue
		}
		c.logMsg("NOTICE", "Connected to %v", address)
		c.tmclient = httpClient
		break
	}

	if c.tmclient == nil {
		c.failedToReconnect = true
		return ErrReconnectFailure
	}

	c.lastReconnection = time.Now()
	return nil
}

// Stop gracefully stops the client
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		if c.tmclient != nil {
			c.tmclient.Stop()
		}
	})
}

// a thread-safe logging
func (c *Client) logMsg(level string, msgfmt string, a ...interface{}) {
	c.logLock.Lock()
	defer c.logLock.Unlock()

	msg := msgfmt
	if a != nil {
		msg = fmt.Sprintf(msgfmt, a...)
	}

	level = strings.ToUpper(level)
	switch level {
	case "DEBUG":
		c.log.Debug(msg)
	case "INFO":
		c.log.Info(msg)
	case "NOTICE":
		c.log.Notice(msg)
	case "WARNING":
		c.log.Warning(msg)
	case "ERROR":
		c.log.Error(msg)
	case "CRITICAL":
		c.log.Critical(msg)
	}
}

// New returns new instance of the client
func New(nodeAddresses []string, logger *logger.Logger) (*Client, error) {
	c := &Client{
		log:               logger.GetLogger("Tendermint-Client"),
		possibleAddresses: nodeAddresses,
		failedToReconnect: false,
		tmclient:          nil, // will be set by the reconnect call
	}

	err := c.reconnect(true)
	if err != nil {
		return nil, errors.New("Could not connect to any defined blockchain node")
	}

	return c, nil
}
