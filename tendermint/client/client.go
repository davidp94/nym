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
	"bytes"

	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/utils"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	tmclient "github.com/tendermint/tendermint/rpc/client"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	"gopkg.in/op/go-logging.v1"
)

type Client struct {
	log *logging.Logger

	tmclient *tmclient.HTTP
}

// temp for debug
func (c *Client) Broadcast(tx []byte) (*ctypes.ResultBroadcastTxCommit, error) {
	return c.tmclient.BroadcastTxCommit(tx)
}

// temp for debug
func (c *Client) SendAsync(tx []byte) (*ctypes.ResultBroadcastTx, error) {
	return c.tmclient.BroadcastTxAsync(tx)
}

// deprecated -> no need for that function anymore
// LookUpZeta checks if given Zeta was already spent (TODO: epochs?)
// transaction is used rather than a simple query in order to ensure there would be no stale results. For example
// there might be an accepted, but not yet commited transaction to spend given credential. Query would return false,
// while lookup as seperate transaction would be properly ordered and return true.
func (c *Client) LookUpZeta(zeta *Curve.ECP) bool {
	c.log.Debugf("Looking up: %v", utils.ToCoconutString(zeta))
	tx := transaction.NewLookUpZetaTx(zeta)
	res, err := c.tmclient.BroadcastTxCommit(tx)

	if err != nil {
		c.log.Errorf("Error response: %v", err)
	}

	if bytes.Equal(res.DeliverTx.Data, transaction.TruthBytes) {
		return true
	}

	if bytes.Equal(res.DeliverTx.Data, transaction.FalseBytes) {
		return false
	}

	c.log.Warningf("UNKNOWN RESPONSE: %v", res.DeliverTx.Data)
	return false

}

func (c *Client) Stop() {
	c.tmclient.Stop()
}

// TODO: replace nodeaddress with cfg?
func New(nodeAddress string, log *logger.Logger) (*Client, error) {
	tmclient := tmclient.NewHTTP(nodeAddress, "/websocket")
	err := tmclient.Start()
	if err != nil {
		return nil, err
	}

	return &Client{
		tmclient: tmclient,
		log:      log.GetLogger("Tendermint-Client"),
	}, nil
}
