// client.go - Ethereum client
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

// package client provides API for communication with an Ethereum blockchain.
package client

// TODO: transfer to pipe, redeem credential calls handling

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"

	"0xacab.org/jstuczyn/CoconutGo/ethereum/erc20/constants"

	token "0xacab.org/jstuczyn/CoconutGo/ethereum/token"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"gopkg.in/op/go-logging.v1"
)

// Client defines necessary attributes for establishing communication with an Ethereum blockchain
// and for performing functions required by the Nym system.
type Client struct {
	nodeAddresses    []string
	privateKey       *ecdsa.PrivateKey
	chainID          *big.Int
	nymTokenIntance  *token.Token
	ethClient        *ethclient.Client
	log              *logging.Logger
	address          common.Address // TODO: remove?
	erc20NymContract common.Address
	pipeAccount      common.Address
}

const (
	// Nym specific
	defaultDecimals    = 18 // TODO: move this one to erc20.constants?
	predefinedGasLimit = 50000
)

// TODO: move to separate token-related package
func getTokenDenomination(decimals int64) *big.Int {
	// return big.NewInt(int64(10) * *18)
	t := new(big.Int)
	// look at: https://github.com/securego/gosec/issues/283
	//nolint: gosec
	t.Exp(big.NewInt(10), big.NewInt(decimals), nil)
	return t
}

// TODO: Since it's literally copied from the main client's code, should we just move it to common or something?
func (c *Client) logAndReturnError(fmtString string, a ...interface{}) error {
	errstr := fmtString
	if a != nil {
		errstr = fmt.Sprintf(fmtString, a...)
	}
	c.log.Error(errstr)
	return errors.New(errstr)
}

// used to get status of transaction, pending, accepted, rejected, etc
func (c *Client) GetTransactionStatus(ctx context.Context, txHash []byte) {
	// TODO:
}

// pending is used to decide whether to query pending balance
func (c *Client) QueryERC20Balance(ctx context.Context, address common.Address, pending bool) (*big.Int, error) {
	balance, err := c.nymTokenIntance.BalanceOf(&bind.CallOpts{
		Pending: pending,
		Context: ctx,
	}, address)

	if err != nil {
		return nil, c.logAndReturnError("QueryERC20Balance: Failed to query balance of %v: %v", address.Hex(), err)
	}

	return balance, nil
}

// TODO: rewrite to use token instance similarly to Balance query?
// TransferERC20Tokens sends specified amount of ERC20 tokens to given account.
func (c *Client) TransferERC20Tokens(ctx context.Context,
	amount int64,
	tokenContract common.Address,
	targetAddress common.Address,
	tokenDecimals ...int,
) error {
	if amount <= 0 {
		return c.logAndReturnError("TransferERC20Tokens: trying to transfer negative number of tokens")
	}

	fromAddress := c.address
	nonce, err := c.ethClient.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return c.logAndReturnError("TransferERC20Tokens: Failed to obtain nonce: %v", err)
	}

	gasPrice, err := c.ethClient.SuggestGasPrice(ctx)
	if err != nil {
		return c.logAndReturnError("TransferERC20Tokens: Failed to obtain gas price: %v", err)
	}

	methodID := constants.MustMethodIDBytes(constants.TransferMethodID)

	var decimals int64
	if len(tokenDecimals) != 1 {
		decimals = defaultDecimals
		c.log.Infof("Assuming target token is using %v decimals", decimals)
	} else {
		decimals = int64(tokenDecimals[0])
		c.log.Infof("Using %v decimals for the token", decimals)
	}
	// padded arguments:
	paddedAddress := common.LeftPadBytes(targetAddress.Bytes(), 32)
	tokenAmount := new(big.Int)
	tokenAmount.Mul(getTokenDenomination(decimals), big.NewInt(amount))

	paddedAmount := common.LeftPadBytes(tokenAmount.Bytes(), 32)

	data := make([]byte, len(methodID)+len(paddedAddress)+len(paddedAmount))
	copy(data, methodID)
	copy(data[len(methodID):], paddedAddress)
	copy(data[len(methodID)+len(paddedAddress):], paddedAmount)

	// from my limited experience the estimation was always lower than what was actually required, so temporarily
	// i've just hardcoded some value, but for future we should probably use the estimation to derive our limit
	gasLimit, err := c.ethClient.EstimateGas(context.Background(), ethereum.CallMsg{
		To:   &targetAddress,
		Data: data,
	})
	if err != nil {
		return c.logAndReturnError("TransferERC20Tokens: Failed to obtain gas estimation: %v", err)
	}
	c.log.Debugf("Estimated gasLimit: %v, using %v instead", gasLimit, predefinedGasLimit)
	gasLimit = predefinedGasLimit

	tx := types.NewTransaction(nonce, tokenContract, big.NewInt(0), gasLimit, gasPrice, data)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(c.chainID), c.privateKey)
	if err != nil {
		return c.logAndReturnError("TransferERC20Tokens: Failed to sign transaction: %v", err)
	}
	if err := c.ethClient.SendTransaction(ctx, signedTx); err != nil {
		return c.logAndReturnError("TransferERC20Tokens: Failed to send transaction: %v", err)
	}
	c.log.Noticef("Sent Transaction with hash: %v", signedTx.Hash().Hex())
	// TODO: perhaps some wait loop to wait for transaction to be accepted/rejected?
	return nil
}

func (c *Client) connect(ctx context.Context, ethHost string) error {
	client, err := ethclient.Dial(ethHost)
	if err != nil {
		errMsg := fmt.Sprintf("Error connecting to Infura: %s", err)
		c.log.Error(errMsg)
		return errors.New(errMsg)
	}

	c.log.Debugf("Connected to %v", ethHost)

	c.ethClient = client

	if c.chainID == nil {
		id, err := client.NetworkID(ctx)
		if err != nil {
			return c.logAndReturnError("Failed to obtain networkID: %v", err)
		}
		c.log.Debugf("Obtained network id: %v", id)
		c.chainID = id
	}

	if c.nymTokenIntance == nil {
		instance, err := token.NewToken(c.erc20NymContract, c.ethClient)
		if err != nil {
			return c.logAndReturnError("Failed to create token instance: %v", err)
		}
		c.nymTokenIntance = instance
	}
	return nil
}

// Config defines configuration for Ethereum Client.
// TODO: if expands too much, move it to a toml file? Or just include it in new section of existing Client toml.
type Config struct {
	privateKey       *ecdsa.PrivateKey
	nodeAddresses    []string
	erc20NymContract common.Address
	pipeAccount      common.Address

	logger *logger.Logger
}

// NewConfig creates new instance of Config struct.
func NewConfig(pk *ecdsa.PrivateKey, nodes []string, erc20, pipeAccount common.Address, logger *logger.Logger) Config {
	cfg := Config{
		privateKey:       pk,
		nodeAddresses:    nodes,
		erc20NymContract: erc20,
		pipeAccount:      pipeAccount,
		logger:           logger,
	}
	return cfg
}

func New(cfg Config) (*Client, error) {
	c := &Client{
		address:          crypto.PubkeyToAddress(*cfg.privateKey.Public().(*ecdsa.PublicKey)),
		privateKey:       cfg.privateKey,
		erc20NymContract: cfg.erc20NymContract,
		pipeAccount:      cfg.pipeAccount,
		nodeAddresses:    cfg.nodeAddresses,
		log:              cfg.logger.GetLogger("Ethereum-Client"),
	}

	// TODO: reconnection, etc as with Tendermint client? Or just have a single node to which we connect and if it
	// fails, it fails (+ actually same consideration for the Tendermint client)
	if err := c.connect(context.TODO(), c.nodeAddresses[0]); err != nil {
		return nil, err
	}

	return c, nil
}
