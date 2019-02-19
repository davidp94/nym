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
	"encoding/binary"

	"0xacab.org/jstuczyn/CoconutGo/common/comm"
	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

func (c *Client) createCredentialRequestSig(cm *Curve.ECP, token *token.Token) []byte {
	cmb := make([]byte, constants.ECPLen)
	cm.ToBytes(cmb, true)
	msg := make([]byte, len(c.nymAccount.PublicKey)+4+constants.ECPLen)
	copy(msg, c.nymAccount.PublicKey)
	binary.BigEndian.PutUint32(msg[len(c.nymAccount.PublicKey):], uint32(token.Value()))
	copy(msg[len(c.nymAccount.PublicKey)+4:], cmb)
	return c.nymAccount.PrivateKey.SignBytes(msg)
}

// GetCredential similarly to previous requests, sends 'getcredential' request
// to all IA servers specified in the config with the provided token and required cryptographic materials.
// Error is returned if insufficient number of responses was received.
func (c *Client) GetCredential(token *token.Token) (token.Credential, error) {
	if c.cfg.Client.UseGRPC {
		return nil, c.logAndReturnError(gRPCClientErr)
	}

	// first check if we have loaded the account information
	if c.nymAccount.PrivateKey == nil || c.nymAccount.PublicKey == nil {
		return nil, c.logAndReturnError("GetCredential: Tried to obtain credential on undefined account")
	}

	lambda, err := c.cryptoworker.CoconutWorker().PrepareBlindSignTokenWrapper(c.elGamalPublicKey, token)
	if err != nil {
		return nil, c.logAndReturnError("GetCredential: Could not create lambda: %v", err)
	}

	sig := c.createCredentialRequestSig(lambda.Cm(), token)

	cmd, err := commands.NewGetCredentialRequest(lambda, c.elGamalPublicKey, token, c.nymAccount.PublicKey, sig)
	if err != nil {
		return nil, c.logAndReturnError("GetCredential: Failed to create GetCredential request: %v", err)
	}

	packetBytes, err := commands.CommandToMarshaledPacket(cmd)
	if err != nil {
		return nil, c.logAndReturnError("GetCredential: Could not create data packet for GetCredential command: %v", err)
	}

	responses := comm.GetServerResponses(
		&comm.RequestParams{
			MarshaledPacket:   packetBytes,
			MaxRequests:       c.cfg.Client.MaxRequests,
			ConnectionTimeout: c.cfg.Debug.ConnectTimeout,
			RequestTimeout:    c.cfg.Debug.RequestTimeout,
			ServerAddresses:   c.cfg.Client.IAAddresses,
			ServerIDs:         c.cfg.Client.IAIDs,
		},
		c.log,
	)

	// what we receive are basically coconut signatures so we can use old logic to parse them.
	sigs, pp := c.parseSignatureServerResponses(responses, c.cfg.Client.Threshold > 0, true)
	return c.handleReceivedSignatures(sigs, pp)
}
