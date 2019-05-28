// nym.go - nym client API
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

// Package client encapsulates all calls to issuers and providers.
package client

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/common/comm"
	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/common/comm/packet"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/query"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	cmn "github.com/tendermint/tendermint/libs/common"
)

func (c *Client) parseCredentialPairResponse(resp *commands.LookUpCredentialResponse,
	elGamalPrivateKey *elgamal.PrivateKey,
) (*coconut.Signature, error) {
	if err := c.checkResponseStatus(resp); err != nil {
		return nil, err
	}
	protoBlindSig := &coconut.ProtoBlindedSignature{}
	if err := proto.Unmarshal(resp.CredentialPair.Credential, protoBlindSig); err != nil {
		return nil, c.logAndReturnError("parseCredentialPairResponse: failed to unmarshal received proto-credential")
	}
	blindSig := &coconut.BlindedSignature{}
	if err := blindSig.FromProto(protoBlindSig); err != nil {
		return nil, c.logAndReturnError("parseCredentialPairResponse: failed to unmarshal received credential")
	}
	return c.cryptoworker.CoconutWorker().UnblindWrapper(blindSig, elGamalPrivateKey), nil
}

func (c *Client) parseLookUpCredentialServerResponses(responses []*comm.ServerResponse,
	elGamalPrivateKey *elgamal.PrivateKey,
) ([]*coconut.Signature, *coconut.PolynomialPoints) {
	if responses == nil {
		return nil, nil
	}

	sigs := make([]*coconut.Signature, 0, len(responses))
	xs := make([]*Curve.BIG, 0, len(responses))
	for i := range responses {
		if responses[i] != nil && responses[i].ServerMetadata != nil {
			if responses[i].ServerMetadata.ID <= 0 {
				c.log.Errorf("Invalid serverID provided: %v", responses[i].ServerMetadata.ID)
				continue
			}

			resp := &commands.LookUpCredentialResponse{}
			if err := proto.Unmarshal(responses[i].MarshaledData, resp); err != nil {
				c.log.Errorf("Failed to unmarshal response from: %v", responses[i].ServerMetadata.Address)
				continue
			}

			var sig *coconut.Signature
			var err error
			sig, err = c.parseCredentialPairResponse(resp, elGamalPrivateKey)
			if err != nil {
				continue
			}
			xs = append(xs, Curve.NewBIGint(responses[i].ServerMetadata.ID))
			sigs = append(sigs, sig)
		}
	}
	return sigs, coconut.NewPP(xs)
}

// GetCurrentERC20Balance gets the current balance of ERC20 tokens associated with the client's address
func (c *Client) GetCurrentERC20Balance() (uint64, error) {
	ctx := context.TODO()
	address := ethcrypto.PubkeyToAddress(*c.privateKey.Public().(*ecdsa.PublicKey))
	balance, err := c.ethClient.QueryERC20Balance(ctx, address, false)
	if err != nil {
		return 0, c.logAndReturnError("GetCurrentERC20Balance: failed to query balance: %v", err)
	}
	t := new(big.Int)
	fullTokens := t.Div(balance, big.NewInt(1000000000000000000))

	return fullTokens.Uint64(), nil
}

// GetCurrentERC20PendingBalance gets the current pending balance of ERC20 tokens associated with the client's address
func (c *Client) GetCurrentERC20PendingBalance() (uint64, error) {
	ctx := context.TODO()
	address := ethcrypto.PubkeyToAddress(*c.privateKey.Public().(*ecdsa.PublicKey))
	balance, err := c.ethClient.QueryERC20Balance(ctx, address, true)
	if err != nil {
		return 0, c.logAndReturnError("GetCurrentERC20PendingBalance: failed to query balance: %v", err)
	}
	t := new(big.Int)
	fullTokens := t.Div(balance, big.NewInt(1000000000000000000))

	return fullTokens.Uint64(), nil
}

// GetCurrentNymBalance gets the current (might be slightly stale due to request being
// sent as a query and not transaction) balance associated with the client's address.
func (c *Client) GetCurrentNymBalance() (uint64, error) {
	address := ethcrypto.PubkeyToAddress(*c.privateKey.Public().(*ecdsa.PublicKey))
	res, err := c.nymClient.Query(query.QueryCheckBalancePath, address[:])
	if err != nil {
		return 0, c.logAndReturnError("GetCurrentNymBalance: failed to send getBalance Query: %v", err)
	}
	if res.Response.Code != code.OK {
		return 0, c.logAndReturnError("GetCurrentNymBalance: the query failed with code %v (%v)",
			res.Response.Code,
			code.ToString(res.Response.Code),
		)
	}
	balance := binary.BigEndian.Uint64(res.Response.Value)
	c.log.Debugf("Queried balance is : %v", balance)
	return balance, nil
}

// public wrapper just for dummy tests
func (c *Client) SendToPipeAccountWrapper(amount int64) error {
	return c.sendToPipeAccount(amount)
}

func (c *Client) sendToPipeAccount(amount int64) error {
	ctx := context.TODO()
	if err := c.ethClient.TransferERC20Tokens(ctx, amount, c.cfg.Nym.NymContract, c.cfg.Nym.PipeAccount); err != nil {
		return err
	}
	return nil
}

func (c *Client) waitForBalanceIncrease() {
	// wait until currentbalance = pendingBalance but make sure our tx is in pending
}

// FIXME:
func (c *Client) createCredentialRequestSig(txHash cmn.HexBytes, nonce []byte, token *token.Token) []byte {
	return nil
	// msg := make([]byte, len(c.nymAccount.PublicKey)+4+len(nonce)+len(txHash))
	// copy(msg, c.nymAccount.PublicKey)
	// binary.BigEndian.PutUint32(msg[len(c.nymAccount.PublicKey):], uint32(token.Value()))
	// copy(msg[len(c.nymAccount.PublicKey)+4:], nonce)
	// copy(msg[len(c.nymAccount.PublicKey)+4+len(nonce):], txHash)
	// return c.nymAccount.PrivateKey.SignBytes(msg)
}

// GetCredential similarly to previous requests, sends 'getcredential' request
// to all IA servers specified in the config with the provided token and required cryptographic materials.
// Error is returned if insufficient number of responses was received.
func (c *Client) GetCredential(token *token.Token) (*coconut.Signature, error) {
	return nil, errors.New("REQUIRES RE-IMPLEMENTATION")

	// if c.cfg.Client.UseGRPC {
	// 	return nil, c.logAndReturnError(gRPCClientErr)
	// }

	// 	elGamalPrivateKey, elGamalPublicKey := c.cryptoworker.CoconutWorker().ElGamalKeygenWrapper()

	// 	// first check if we have loaded the account information
	// 	if c.nymAccount.PrivateKey == nil || c.nymAccount.PublicKey == nil {
	// 		return nil, c.logAndReturnError("GetCredential: Tried to obtain credential on undefined account")
	// 	}

	// 	// we transfer amount of tokens to the Pipe account
	// 	height, err := c.transferTokensToPipe(token, elGamalPublicKey)
	// 	if err != nil {
	// 		return nil, c.logAndReturnError("GetCredential: could not transfer to the Pipe account: %v", err)
	// 	}

	// 	if height <= 1 {
	// 		return nil, c.logAndReturnError("GetCredential: tx was included at invalid height: %v", height)
	// 	}

	// 	// TODO: if there's a failure anywhere beyond this point, we must be able to return height and elgamal keypair
	// 	// so that client could theoretically retry at later time

	// 	c.log.Debugf("Our tx was included in block: %v", height)

	// 	cmd, err := commands.NewLookUpCredentialRequest(height, elGamalPublicKey)
	// 	if err != nil {
	// 		return nil, c.logAndReturnError("GetCredential: Failed to create BlindSign request: %v", err)
	// 	}

	// 	packetBytes, err := commands.CommandToMarshalledPacket(cmd)
	// 	if err != nil {
	// 		return nil, c.logAndReturnError("GetCredential: Could not create data packet for look up credential command: %v", err)
	// 	}

	// 	for i := 0; i < c.cfg.Debug.NumberOfLookUpRetries; i++ {
	// 		c.log.Debug("Waiting for %v", time.Millisecond*time.Duration(c.cfg.Debug.LookUpBackoff))
	// 		time.Sleep(time.Millisecond * time.Duration(c.cfg.Debug.LookUpBackoff))
	// 		c.log.Notice("Going to send look up credential request to %v IAs", len(c.cfg.Client.IAAddresses))

	// 		responses := comm.GetServerResponses(
	// 			&comm.RequestParams{
	// 				MarshaledPacket:   packetBytes,
	// 				MaxRequests:       c.cfg.Client.MaxRequests,
	// 				ConnectionTimeout: c.cfg.Debug.ConnectTimeout,
	// 				RequestTimeout:    c.cfg.Debug.RequestTimeout,
	// 				ServerAddresses:   c.cfg.Client.IAAddresses,
	// 				ServerIDs:         c.cfg.Client.IAIDs,
	// 			},
	// 			c.log,
	// 		)

	// 		sig, err := c.handleReceivedSignatures(c.parseLookUpCredentialServerResponses(responses, elGamalPrivateKey))
	// 		if err != nil {
	// 			continue
	// 		}
	// 		return sig, nil
	// 	}

	// 	// todo: somehow return gamma and height in response rather than in error message
	// 	return nil, c.logAndReturnError(`GetCredential: Could not communicate with enough IAs to obtain credentials.
	// Token was spent in block: %v and gamma used was: %v`, cmd.Height, cmd.Gamma)
}

// TODO: at later date, though we possibly might even ignore it

// // GetCredentialGrpc similarly to previous requests, sends 'getcredential' request
// // to all IA-grpc servers specified in the config with the provided token and required cryptographic materials.
// // Error is returned if insufficient number of responses was received.
// func (c *Client) GetCredentialGrpc(token *token.Token) (token.Credential, error) {
// 	if !c.cfg.Client.UseGRPC {
// 		return nil, c.logAndReturnError(nonGRPCClientErr)
// 	}

// 	elGamalPrivateKey, elGamalPublicKey := c.cryptoworker.CoconutWorker().ElGamalKeygenWrapper()

// 	grpcDialOptions := c.defaultDialOptions
// 	isThreshold := c.cfg.Client.Threshold > 0

// 	// first check if we have loaded the account information
// 	if c.nymAccount.PrivateKey == nil || c.nymAccount.PublicKey == nil {
// 		return nil, c.logAndReturnError("GetCredentialGrpc: Tried to obtain credential on undefined account")
// 	}

// 	lambda, err := c.cryptoworker.CoconutWorker().PrepareBlindSignTokenWrapper(elGamalPublicKey, token)
// 	if err != nil {
// 		return nil, c.logAndReturnError("GetCredential: Could not create lambda: %v", err)
// 	}

// 	reqSig := c.createCredentialRequestSig(lambda.Cm(), token)

// getCredentialRequest, err := commands.NewGetCredentialRequest(
// 	lambda,
// 	elGamalPublicKey,
// 	token,
// 	c.nymAccount.PublicKey,
// 	reqSig,
// )
// 	if err != nil {
// 		return nil, c.logAndReturnError("GetCredential: Failed to create GetCredential request: %v", err)
// 	}

// 	c.log.Notice("Going to send Get Credential request (via gRPCs) to %v IAs", len(c.cfg.Client.IAgRPCAddresses))
// 	responses := c.getGrpcResponses(grpcDialOptions, getCredentialRequest)

// 	sigs := make([]*coconut.Signature, 0, len(c.cfg.Client.IAgRPCAddresses))
// 	xs := make([]*Curve.BIG, 0, len(c.cfg.Client.IAgRPCAddresses))

// 	for i := range responses {
// 		if responses[i] == nil {
// 			c.log.Error("nil response received")
// 			continue
// 		}
// 		// needs updating
// 		sig, err := c.parseBlindSignResponse(responses[i].Message.(*commands.GetCredentialResponse), elGamalPrivateKey)
// 		if err != nil {
// 			continue
// 		}
// 		sigs = append(sigs, sig)
// 		if isThreshold {
// 			xs = append(xs, Curve.NewBIGint(responses[i].ServerMetadata.ID))
// 		}
// 	}
// 	if c.cfg.Client.Threshold > 0 {
// 		return c.handleReceivedSignatures(sigs, coconut.NewPP(xs))
// 	}
// 	return c.handleReceivedSignatures(sigs, nil)
// }

func (c *Client) transferTokensToPipe(token *token.Token, egPub *elgamal.PublicKey) (int64, error) {
	return -1, errors.New("REQUIRES RE-IMPLEMENTATION")
	// first check if we have loaded the account information
	// if c.nymAccount.PrivateKey == nil || c.nymAccount.PublicKey == nil {
	// 	return -1, c.logAndReturnError("transferTokensToPipe: Tried to obtain credential on undefined account")
	// }

	// lambda, err := c.cryptoworker.CoconutWorker().PrepareBlindSignTokenWrapper(egPub, token)
	// if err != nil {
	// 	return -1, c.logAndReturnError("GetCredential: Could not create lambda: %v", err)
	// }

	// pubM, _ := token.GetPublicAndPrivateSlices()

	// transferToPipeRequestParams := transaction.TransferToPipeRequestParams{
	// 	Acc:    c.nymAccount,
	// 	Amount: token.Value(),
	// 	EgPub:  egPub,
	// 	Lambda: lambda,
	// 	PubM:   pubM,
	// }

	// req, err := transaction.CreateNewTransferToPipeRequest(transferToPipeRequestParams)
	// if err != nil {
	// 	return -1, c.logAndReturnError("transferTokensToPipe: Failed to create request: %v", err)
	// }

	// res, err := c.nymClient.Broadcast(req)
	// if err != nil {
	// 	return -1, c.logAndReturnError("transferTokensToPipe: Failed to send request to the blockchain: %v", err)
	// }
	// if res.DeliverTx.Code != code.OK {
	// 	return -1, c.logAndReturnError("transferTokensToPipe: Failed to send request to the blockchain: %v - %v",
	// 		res.DeliverTx.Code,
	// 		code.ToString(res.DeliverTx.Code),
	// 	)
	// }

	// return res.Height, nil
}

func (c *Client) parseSpendCredentialResponse(packetResponse *packet.Packet) (bool, error) {
	spendCredentialResponse := &commands.SpendCredentialResponse{}
	if err := proto.Unmarshal(packetResponse.Payload(), spendCredentialResponse); err != nil {
		return false, c.logAndReturnError("parseSpendCredentialResponse: Failed to recover spend credential result: %v", err)
	} else if spendCredentialResponse.GetStatus().Code != int32(commands.StatusCode_OK) {
		return false, c.logAndReturnError(
			"parseSpendCredentialResponse: Received invalid response with status: %v. Error: %v",
			spendCredentialResponse.GetStatus().Code,
			spendCredentialResponse.GetStatus().Message,
		)
	}
	return spendCredentialResponse.WasSuccessful, nil
}

func (c *Client) prepareSpendCredentialRequest(
	token *token.Token,
	sig *coconut.Signature,
	vk *coconut.VerificationKey,
	providerAddress []byte,
) (*commands.SpendCredentialRequest, error) {
	var err error
	if vk == nil {
		if c.cfg.Client.UseGRPC {
			vk, err = c.GetAggregateVerificationKeyGrpc()
		} else {
			vk, err = c.GetAggregateVerificationKey()
		}
		if err != nil {
			return nil,
				c.logAndReturnError("prepareSpendCredentialRequest: "+
					"Could not obtain aggregate verification key required to create proofs for verification: %v",
					err,
				)
		}
	}

	pubM, privM := token.GetPublicAndPrivateSlices()
	theta, err := c.cryptoworker.CoconutWorker().ShowBlindSignatureTumblerWrapper(vk, sig, privM, providerAddress)
	if err != nil {
		return nil,
			c.logAndReturnError("prepareSpendCredentialRequest: Failed when creating proofs for verification: %v", err)
	}

	spendCredentialRequest, err := commands.NewSpendCredentialRequest(sig, pubM, theta, token.Value(), providerAddress)
	if err != nil {
		return nil,
			c.logAndReturnError("prepareSpendCredentialRequest: Failed to create SpendCredential request: %v", err)
	}
	return spendCredentialRequest, nil
}

// SpendCredential sends a TCP request to spend an issued credential at a particular provider.
//nolint: dupl
func (c *Client) SpendCredential(
	token *token.Token, // token on which the credential is issued; encapsulates required attributes
	credential *coconut.Signature, // the credential to be spent
	address string, // physical address of the merchant to which we send the request
	providerAccountAddress []byte, // blockchain address of the merchant to which the proof will be bound
	vk *coconut.VerificationKey, // aggregate verification key of the issuers in the system
) (bool, error) {
	if c.cfg.Client.UseGRPC {
		return false, c.logAndReturnError(gRPCClientErr)
	}

	spendCredentialRequest, err := c.prepareSpendCredentialRequest(token, credential, vk, providerAccountAddress)
	if err != nil {
		return false, c.logAndReturnError("SpendCredential: Failed to prepare spendCredentialRequest: %v", err)
	}

	packetBytes, err := commands.CommandToMarshalledPacket(spendCredentialRequest)
	if err != nil {
		return false, c.logAndReturnError("Could not create data packet for spend credential command: %v", err)
	}

	c.log.Debugf("Dialing %v", address)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return false, c.logAndReturnError("SpendCredential: Could not dial %v (%v)", address, err)
	}

	// currently will never be thrown since there is no writedeadline
	if _, werr := conn.Write(packetBytes); werr != nil {
		return false,
			c.logAndReturnError("SpendCredential: Failed to write to connection: %v", werr)
	}

	sderr := conn.SetReadDeadline(time.Now().Add(time.Duration(c.cfg.Debug.ConnectTimeout) * time.Millisecond))
	if sderr != nil {
		return false,
			c.logAndReturnError("SpendCredential: Failed to set read deadline for connection: %v",
				sderr)
	}

	resp, err := comm.ReadPacketFromConn(conn)
	if err != nil {
		return false,
			c.logAndReturnError("SpendCredential: Received invalid response from %v: %v", address, err)
	}

	return c.parseSpendCredentialResponse(resp)
}

// SpendCredentialGrpc sends a gRPC request to spend an issued credential at a particular provider.
func (c *Client) SpendCredentialGrpc(token *token.Token, credential *coconut.Signature, providerAddress []byte) error {
	if !c.cfg.Client.UseGRPC {
		return c.logAndReturnError(nonGRPCClientErr)
	}

	return nil // not implemeneted
}
