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
	"context"
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

// TODO: handle reconnect infinite loop

const (
	reconnectionValidityPeriod = time.Second * 10
)

// Client encapsulates all necessary data for communicating with the blockchain application by possibly multiple
// clients simultaneously.
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
	c.logMsg("DEBUG", "Broadcasting a TX")
	var res *ctypes.ResultBroadcastTxCommit
	var err error
	if c.tmclient != nil && c.tmclient.IsRunning() {
		res, err = c.tmclient.BroadcastTxCommit(tx)
	} else { // reconnection is most likely already in progress
		err = errors.New("Invalid client - reconnection required")
	}
	// network error
	if err != nil {
		c.logMsg("DEBUG", "Network error while sending tx to the ABCI: %v", err)
		err := c.reconnect(false)
		if err != nil {
			// workers should decide how to handle it
			return nil, err
		}
		// try to send the tx again
		return c.Broadcast(tx)
	}
	c.logMsg("DEBUG", "Broadcast call done")
	return res, err
}

// SendSync sends an sync transaction to specified blockchain node. Note that there is no guarantee the transaction
// succeeded, but it definitely passed CheckTx and was included in the mempool. However, it still
// might return an error at DeliverTx.
func (c *Client) SendSync(tx []byte) (*ctypes.ResultBroadcastTx, error) {
	c.logMsg("DEBUG", "Sending a Sync TX")
	var res *ctypes.ResultBroadcastTx
	var err error
	if c.tmclient != nil && c.tmclient.IsRunning() {
		res, err = c.tmclient.BroadcastTxSync(tx)
	} else { // reconnection is most likely already in progress
		err = errors.New("Invalid client - reconnection required")
	}
	// network error
	if err != nil {
		c.logMsg("DEBUG", "Network error while sending tx to the ABCI: %v", err)
		err := c.reconnect(false)
		if err != nil {
			// workers should decide how to handle it
			return nil, err
		}
		// try to send the tx again
		return c.SendSync(tx)
	}
	c.logMsg("DEBUG", "SendSync call done")
	return res, err
}

// SendAsync sends an async transaction to specified blockchain node. Note that there is no guarantee the transaction
// was included on the chain (it might not have been even added to the mempool because it could have failed CheckTx)
func (c *Client) SendAsync(tx []byte) (*ctypes.ResultBroadcastTx, error) {
	c.logMsg("DEBUG", "Sending an async TX")
	var res *ctypes.ResultBroadcastTx
	var err error
	if c.tmclient != nil && c.tmclient.IsRunning() {
		res, err = c.tmclient.BroadcastTxAsync(tx)
	} else { // reconnection is most likely already in progress
		err = errors.New("Invalid client - reconnection required")
	}
	// network error
	if err != nil {
		c.logMsg("DEBUG", "Network error while sending tx to the ABCI: %v", err)
		err := c.reconnect(false)
		if err != nil {
			// workers should decide how to handle it
			return nil, err
		}
		// try to send the tx again
		return c.SendAsync(tx)
	}
	c.logMsg("DEBUG", "SendAsync call done")
	return res, err
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
		c.logMsg("DEBUG", "Network error while quering the ABCI: %v", err)
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

// TxByHash queries the chain to get particular tx results given its hash.
func (c *Client) TxByHash(hash cmn.HexBytes) (*ctypes.ResultTx, error) {
	c.logMsg("DEBUG", "Looking up Tx by its hash: %v", hash)
	var res *ctypes.ResultTx
	var err error
	if c.tmclient != nil && c.tmclient.IsRunning() {
		res, err = c.tmclient.Tx(hash, true)
	} else { // reconnection is most likely already in progress
		err = errors.New("Invalid client - reconnection required")
	}
	// network error
	if err != nil {
		c.logMsg("DEBUG", "Network error while getting tx result: %v", err)
		err := c.reconnect(false)
		if err != nil {
			// workers should decide how to handle it
			return nil, err
		}
		// repeat the query
		return c.TxByHash(hash)
	}
	c.logMsg("DEBUG", "TxByHash call done")
	return res, err
}

// BlockchainInfo return block headers from the specified range.
// Note: according to the docs it can only return up to 20 results.
func (c *Client) BlockchainInfo(minHeight, maxHeight int64) (*ctypes.ResultBlockchainInfo, error) {
	c.logMsg("DEBUG", "Getting all block headers from %v to %v", minHeight, maxHeight)
	var res *ctypes.ResultBlockchainInfo
	var err error
	if c.tmclient != nil && c.tmclient.IsRunning() {
		res, err = c.tmclient.BlockchainInfo(minHeight, maxHeight)
	} else { // reconnection is most likely already in progress
		err = errors.New("Invalid client - reconnection required")
	}
	// network error
	if err != nil {
		c.logMsg("DEBUG", "Network error while getting tx result: %v", err)
		err := c.reconnect(false)
		if err != nil {
			// workers should decide how to handle it
			return nil, err
		}
		// repeat the query
		return c.BlockchainInfo(minHeight, maxHeight)
	}
	c.logMsg("DEBUG", "BlockchainInfo call done")
	return res, err
}

// BlockResults results from a block at given height.
func (c *Client) BlockResults(height int64) (*ctypes.ResultBlockResults, error) {
	c.logMsg("DEBUG", "Getting all results from height %v", height)
	var res *ctypes.ResultBlockResults
	var err error
	if c.tmclient != nil && c.tmclient.IsRunning() {
		// TODO: why is it taking pointer to int64??
		res, err = c.tmclient.BlockResults(&height)
	} else { // reconnection is most likely already in progress
		err = errors.New("Invalid client - reconnection required")
	}
	// network error
	if err != nil {
		c.logMsg("DEBUG", "Network error while getting tx result: %v", err)
		err := c.reconnect(false)
		if err != nil {
			// workers should decide how to handle it
			return nil, err
		}
		// repeat the query
		return c.BlockResults(height)
	}
	c.logMsg("DEBUG", "BlockResults call done")
	return res, err
}

func (c *Client) reconnect(forceTry bool) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	c.logMsg("NOTICE", "Trying to reconnect to any working blockchain node")

	if c.lastReconnection.Add(reconnectionValidityPeriod).UnixNano() > time.Now().UnixNano() {
		// somebody else already caused reconnection
		c.logMsg("DEBUG", "Another instance already reconnected")
		time.Sleep(time.Second * 1)
		return nil
	}

	// so that we would not try connecting with all addresses as somebody else already tried and failed
	if !forceTry && c.failedToReconnect {
		return ErrReconnectFailure
	}

	// we could try to reconnect to existing one, hoping itd come back, but might as well connect to another node
	if c.tmclient != nil {
		// err is only returned of client is already stopped, so we can safely ignore it
		// nolint: gosec
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

// Subscribe is a wrapper for the websocket subscribe method.
func (c *Client) Subscribe(ctx context.Context, subscriber, query string,
	outCapacity ...int) (out <-chan ctypes.ResultEvent, err error) {
	return c.tmclient.Subscribe(ctx, subscriber, query, outCapacity...)
}

// Unsubscribe is a wrapper for the websocket unsubscribe method.
func (c *Client) Unsubscribe(ctx context.Context, subscriber, query string) error {
	return c.tmclient.Unsubscribe(ctx, subscriber, query)
}

// UnsubscribeAll is a wrapper for the websocket unsubscribeAll method.
func (c *Client) UnsubscribeAll(ctx context.Context, subscriber string) error {
	return c.tmclient.UnsubscribeAll(ctx, subscriber)
}

// Stop gracefully stops the client
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		if c.tmclient != nil {
			// err is only returned of client is already stopped, so we can safely ignore it
			// nolint: gosec
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
