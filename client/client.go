// client.go - coconut client API
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

// Package client encapsulates all calls to issuers and providers.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/client/config"
	"0xacab.org/jstuczyn/CoconutGo/client/cryptoworker"
	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	pb "0xacab.org/jstuczyn/CoconutGo/server/comm/grpc/services"
	"0xacab.org/jstuczyn/CoconutGo/server/comm/utils"
	"0xacab.org/jstuczyn/CoconutGo/server/commands"
	"0xacab.org/jstuczyn/CoconutGo/server/packet"
	"github.com/golang/protobuf/proto"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"google.golang.org/grpc"
	"gopkg.in/op/go-logging.v1"
)

// Client represents an user of Coconut network
type Client struct {
	cfg *config.Config
	log *logging.Logger

	elGamalPrivateKey *elgamal.PrivateKey
	elGamalPublicKey  *elgamal.PublicKey

	cryptoworker       *cryptoworker.Worker
	defaultDialOptions []grpc.DialOption
}

const (
	nonGRPCClientErr = "Non-gRPC client trying to call gRPC method"
	gRPCClientErr    = "gRPC client trying to call non-gRPC method"
)

func (c *Client) checkResponseStatus(resp commands.ProtoResponse) error {
	if resp == nil || resp.GetStatus() == nil {
		return c.logAndReturnError("checkResponseStatus: Received response (or part of it) was nil")
	}
	if resp.GetStatus().Code != int32(commands.StatusCode_OK) {
		return c.logAndReturnError(
			"checkResponseStatus: Received invalid response with status: %v. Error: %v",
			resp.GetStatus().Code,
			resp.GetStatus().Message,
		)
	}
	return nil
}

func (c *Client) parseVkResponse(resp *commands.VerificationKeyResponse) (*coconut.VerificationKey, error) {
	if err := c.checkResponseStatus(resp); err != nil {
		return nil, err
	}
	vk := &coconut.VerificationKey{}
	if err := vk.FromProto(resp.Vk); err != nil {
		return nil, c.logAndReturnError("parseVkResponse: Failed to unmarshal received verification key")
	}
	return vk, nil
}

func (c *Client) parseSignResponse(resp *commands.SignResponse) (*coconut.Signature, error) {
	if err := c.checkResponseStatus(resp); err != nil {
		return nil, err
	}
	sig := &coconut.Signature{}
	if err := sig.FromProto(resp.Sig); err != nil {
		return nil, c.logAndReturnError("parseSignResponse: Failed to unmarshal received signature")
	}
	return sig, nil
}

func (c *Client) parseBlindSignResponse(resp *commands.BlindSignResponse) (*coconut.Signature, error) {
	if err := c.checkResponseStatus(resp); err != nil {
		return nil, err
	}
	blindSig := &coconut.BlindedSignature{}
	if err := blindSig.FromProto(resp.Sig); err != nil {
		return nil, c.logAndReturnError("parseBlindSignResponse: Failed to unmarshal received signature")
	}
	return c.cryptoworker.CoconutWorker().UnblindWrapper(blindSig, c.elGamalPrivateKey), nil
}

func (c *Client) getGrpcResponses(dialOptions []grpc.DialOption, request proto.Message) []*utils.ServerResponseGrpc {
	responses := make([]*utils.ServerResponseGrpc, len(c.cfg.Client.IAgRPCAddresses))
	respCh := make(chan *utils.ServerResponseGrpc)
	reqCh, cancelFuncs := c.sendGRPCs(respCh, dialOptions)

	go func() {
		for i := range c.cfg.Client.IAgRPCAddresses {
			c.log.Debug("Writing request to %v", c.cfg.Client.IAgRPCAddresses[i])
			reqCh <- &utils.ServerRequestGrpc{
				Message:       request,
				ServerAddress: c.cfg.Client.IAgRPCAddresses[i],
				ServerID:      c.cfg.Client.IAIDs[i],
			}
		}
	}()

	c.waitForGrpcResponses(respCh, responses, cancelFuncs)
	close(reqCh)
	return responses
}

// nolint: lll
func (c *Client) waitForGrpcResponses(respCh <-chan *utils.ServerResponseGrpc, responses []*utils.ServerResponseGrpc, cancelFuncs []context.CancelFunc) {
	i := 0
	for {
		select {
		case resp := <-respCh:
			c.log.Debug("Received a reply from IA (%v)", resp.ServerAddress)
			responses[i] = resp
			i++

			if i == len(responses) {
				c.log.Debug("Got responses from all servers")
				return
			}
		case <-time.After(time.Duration(c.cfg.Debug.RequestTimeout) * time.Millisecond):
			c.log.Notice("Timed out while sending requests. Cancelling all requests in progress.")
			for _, cancel := range cancelFuncs {
				cancel()
			}
			return
		}
	}
}

// errcheck is ignored to make it not complain about not checking for err in conn.Close()
// nolint: lll, errcheck
func (c *Client) sendGRPCs(respCh chan<- *utils.ServerResponseGrpc, dialOptions []grpc.DialOption) (chan<- *utils.ServerRequestGrpc, []context.CancelFunc) {
	reqCh := make(chan *utils.ServerRequestGrpc)

	// there can be at most that many connections active at given time,
	// as each goroutine can only access a single index and will overwrite its previous entry
	cancelFuncs := make([]context.CancelFunc, c.cfg.Client.MaxRequests)

	for i := 0; i < c.cfg.Client.MaxRequests; i++ {
		go func(i int) {
			for {
				req, ok := <-reqCh
				if !ok {
					return
				}
				c.log.Debugf("Dialing %v", req.ServerAddress)
				conn, err := grpc.Dial(req.ServerAddress, dialOptions...)
				if err != nil {
					c.log.Errorf("Could not dial %v (%v)", req.ServerAddress, err)
				}

				defer conn.Close()

				// in the case of a provider, it will be sent to a single server so no need to make it possible to include it in the loop
				cc := pb.NewIssuerClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(c.cfg.Debug.ConnectTimeout))
				cancelFuncs[i] = cancel
				defer func() {
					cancelFuncs[i] = nil
					cancel()
				}()

				var resp proto.Message
				var errgrpc error
				switch reqt := req.Message.(type) {
				case *commands.SignRequest:
					resp, errgrpc = cc.SignAttributes(ctx, reqt)
				case *commands.VerificationKeyRequest:
					resp, errgrpc = cc.GetVerificationKey(ctx, reqt)
				case *commands.BlindSignRequest:
					resp, errgrpc = cc.BlindSignAttributes(ctx, reqt)
				default:
					errstr := fmt.Sprintf("Unknown command was passed: %v", reflect.TypeOf(req.Message))
					errgrpc = errors.New(errstr)
					c.log.Warning(errstr)
				}
				if errgrpc != nil {
					c.log.Errorf("Failed to obtain signature from %v, err: %v", req.ServerAddress, err)
				} else {
					respCh <- &utils.ServerResponseGrpc{Message: resp, ServerID: req.ServerID, ServerAddress: req.ServerAddress}
				}
			}
		}(i)
	}
	return reqCh, cancelFuncs
}

// nolint: lll
// currently it tries to parse everything and just ignores an invalid request, should it fail on any single invalid request?
func (c *Client) parseSignatureServerResponses(responses []*utils.ServerResponse, isThreshold bool, isBlind bool) ([]*coconut.Signature, *coconut.PolynomialPoints) {
	if responses == nil {
		return nil, nil
	}

	sigs := make([]*coconut.Signature, 0, len(responses))
	xs := make([]*Curve.BIG, 0, len(responses))
	for i := range responses {
		if responses[i] != nil {
			if responses[i].ServerID <= 0 {
				c.log.Errorf("Invalid serverID provided: %v", responses[i].ServerID)
				if !isThreshold {
					c.log.Error("Not a threshold system: can't get all signatures")
					return nil, nil
				}
				continue
			}

			var resp commands.ProtoResponse
			if isBlind {
				resp = &commands.BlindSignResponse{}
			} else {
				resp = &commands.SignResponse{}
			}
			if err := proto.Unmarshal(responses[i].MarshaledData, resp); err != nil {
				c.log.Errorf("Failed to unmarshal response from: %v", responses[i].ServerAddress)
				continue
			}

			var sig *coconut.Signature
			var err error
			if isBlind {
				sig, err = c.parseBlindSignResponse(resp.(*commands.BlindSignResponse))
				if err != nil {
					continue
				}
			} else {
				sig, err = c.parseSignResponse(resp.(*commands.SignResponse))
				if err != nil {
					continue
				}
			}

			if isThreshold {
				xs = append(xs, Curve.NewBIGint(responses[i].ServerID))
			}
			sigs = append(sigs, sig)
		}
	}
	if isThreshold {
		return sigs, coconut.NewPP(xs)
	}
	if len(sigs) != len(responses) {
		c.log.Errorf("This is not threshold system and some of the received responses were invalid")
		return nil, nil
	}
	return sigs, nil
}

func (c *Client) handleIds(pp *coconut.PolynomialPoints) (map[int]bool, error) {
	seenIds := make(map[string]bool)
	entriesToRemove := make(map[int]bool)

	if pp != nil {
		for i, id := range pp.Xs() {
			if id == nil {
				// we ignore that entry
				entriesToRemove[i] = true
				continue
			}
			// converting it to bytes is order of magnitude quicker than converting to string with BIG.ToString
			b := make([]byte, constants.BIGLen)
			id.ToBytes(b)
			s := string(b)
			if _, ok := seenIds[s]; ok {
				return nil, c.logAndReturnError("handleIds: Multiple responses from server with ID: %v", id.ToString())
			}
			seenIds[s] = true
		}
	} else {
		// we assume all sigs are 'valid', but system cannot be threshold
		if c.cfg.Client.Threshold > 0 {
			return nil, c.logAndReturnError("handleIds: This is a threshold system, yet received no server IDs!")
		}
	}
	return entriesToRemove, nil
}

// nolint: lll, gocyclo
func (c *Client) handleReceivedSignatures(sigs []*coconut.Signature, pp *coconut.PolynomialPoints) (*coconut.Signature, error) {
	if len(sigs) <= 0 {
		return nil, c.logAndReturnError("handleReceivedSignatures: No signatures provided")
	}

	if c.cfg.Client.Threshold == 0 && pp != nil {
		return nil, c.logAndReturnError("handleReceivedSignatures: Passed pp to a non-threshold system")
	}

	entriesToRemove, err := c.handleIds(pp)
	if err != nil {
		return nil, err
	}

	for i := range sigs {
		if sigs[i] == nil || sigs[i].Sig1() == nil || sigs[i].Sig2() == nil {
			entriesToRemove[i] = true
		}
	}

	if len(entriesToRemove) > 0 {
		if c.cfg.Client.Threshold > 0 {
			newXs := pp.Xs()
			for i := range entriesToRemove {
				newXs = append(newXs[:i], newXs[i+1:]...)
			}
			pp = coconut.NewPP(newXs)
		}
		for i := range entriesToRemove {
			sigs = append(sigs[:i], sigs[i+1:]...)
		}
	}

	if len(sigs) >= c.cfg.Client.Threshold && len(sigs) > 0 {
		if c.cfg.Client.Threshold > 0 && len(sigs) != len(pp.Xs()) {
			return nil, c.logAndReturnError("handleReceivedSignatures: Inconsistent response, sigs: %v, pp: %v\n", len(sigs), len(pp.Xs()))
		}
		c.log.Notice("Number of signatures received is within threshold")
	} else {
		return nil, c.logAndReturnError("handleReceivedSignatures: Received less than threshold number of signatures")
	}

	// we only want threshold number of them, in future randomly choose them?
	if c.cfg.Client.Threshold > 0 {
		sigs = sigs[:c.cfg.Client.Threshold]
		pp = coconut.NewPP(pp.Xs()[:c.cfg.Client.Threshold])
	} else if (!c.cfg.Client.UseGRPC && len(sigs) != len(c.cfg.Client.IAAddresses)) || (c.cfg.Client.UseGRPC && len(sigs) != len(c.cfg.Client.IAgRPCAddresses)) {
		c.log.Error("No threshold, but obtained only %v out of %v signatures", len(sigs), len(c.cfg.Client.IAAddresses))
		c.log.Warning("This behaviour is currently undefined by requirements.")
		// should it continue regardless and assume the servers are down permanently or just terminate?
	}

	aSig := c.cryptoworker.CoconutWorker().AggregateSignaturesWrapper(sigs, pp)
	c.log.Debugf("Aggregated %v signatures (threshold: %v)", len(sigs), c.cfg.Client.Threshold)

	rSig := c.cryptoworker.CoconutWorker().RandomizeWrapper(aSig)
	c.log.Debug("Randomized the signature")

	return rSig, nil
}

// SignAttributesGrpc sends sign request to all IA-grpc servers specified in the config
// with given set of public attributes.
// In the case of threshold system, first t results are aggregated and the result is randomized and returned.
// Otherwise all results are aggregated and then randomized.
// Error is returned if insufficient number of signatures was received.
func (c *Client) SignAttributesGrpc(pubM []*Curve.BIG) (*coconut.Signature, error) {
	if !c.cfg.Client.UseGRPC {
		return nil, c.logAndReturnError(nonGRPCClientErr)
	}

	grpcDialOptions := c.defaultDialOptions
	isThreshold := c.cfg.Client.Threshold > 0

	signRequest, err := commands.NewSignRequest(pubM)
	if err != nil {
		return nil, c.logAndReturnError("SignAttributesGrpc: Failed to create Sign request: %v", err)
	}

	c.log.Notice("Going to send Sign request (via gRPCs) to %v IAs", len(c.cfg.Client.IAgRPCAddresses))
	responses := c.getGrpcResponses(grpcDialOptions, signRequest)

	sigs := make([]*coconut.Signature, 0, len(c.cfg.Client.IAgRPCAddresses))
	xs := make([]*Curve.BIG, 0, len(c.cfg.Client.IAgRPCAddresses))

	for i := range responses {
		if responses[i] == nil {
			c.log.Error("nil response received")
			continue
		}
		sig, err := c.parseSignResponse(responses[i].Message.(*commands.SignResponse))
		if err != nil {
			continue
		}
		sigs = append(sigs, sig)
		if isThreshold {
			xs = append(xs, Curve.NewBIGint(responses[i].ServerID))
		}
	}
	if c.cfg.Client.Threshold > 0 {
		return c.handleReceivedSignatures(sigs, coconut.NewPP(xs))
	}
	return c.handleReceivedSignatures(sigs, nil)
}

// SignAttributes sends sign request to all IA servers specified in the config
// using TCP sockets with given set of public attributes.
// In the case of threshold system, first t results are aggregated and the result is randomized and returned.
// Otherwise all results are aggregated and then randomized.
// Error is returned if insufficient number of signatures was received.
func (c *Client) SignAttributes(pubM []*Curve.BIG) (*coconut.Signature, error) {
	if c.cfg.Client.UseGRPC {
		return nil, c.logAndReturnError(gRPCClientErr)
	}

	cmd, err := commands.NewSignRequest(pubM)
	if err != nil {
		return nil, c.logAndReturnError("SignAttributes: Failed to create Sign request: %v", err)
	}

	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.SignID)
	if packetBytes == nil {
		return nil, c.logAndReturnError("SignAttributes: Could not create data packet for sign command")
	}

	c.log.Notice("Going to send Sign request (via TCP socket) to %v IAs", len(c.cfg.Client.IAAddresses))
	responses := utils.GetServerResponses(
		packetBytes,
		c.cfg.Client.MaxRequests,
		c.log,
		c.cfg.Debug.ConnectTimeout,
		c.cfg.Debug.RequestTimeout,
		c.cfg.Client.IAAddresses,
		c.cfg.Client.IAIDs,
	)
	return c.handleReceivedSignatures(c.parseSignatureServerResponses(responses, c.cfg.Client.Threshold > 0, false))
}

// nolint: lll, gocyclo
func (c *Client) handleReceivedVerificationKeys(vks []*coconut.VerificationKey, pp *coconut.PolynomialPoints, shouldAggregate bool) ([]*coconut.VerificationKey, error) {
	if vks == nil {
		return nil, c.logAndReturnError("handleReceivedVerificationKeys: No verification keys provided")
	}

	if c.cfg.Client.Threshold == 0 && pp != nil {
		return nil, c.logAndReturnError("handleReceivedVerificationKeys: Passed pp to a non-threshold system")
	}

	entriesToRemove, err := c.handleIds(pp)
	if err != nil {
		return nil, err
	}

	betalen := -1
	for i := range vks {
		if !vks[i].Validate() {
			// the entire key is invalid
			entriesToRemove[i] = true
		} else {
			if betalen == -1 { // only on first run
				betalen = len(vks[i].Beta())
				// we don't know which subset is correct - abandon further execution
			} else if betalen != len(vks[i].Beta()) {
				return nil, c.logAndReturnError("handleReceivedVerificationKeys: verification keys of inconsistent lengths provided")
			}
		}
	}

	if len(entriesToRemove) > 0 {
		if c.cfg.Client.Threshold > 0 {
			newXs := pp.Xs()
			for i := range entriesToRemove {
				newXs = append(newXs[:i], newXs[i+1:]...)
			}
			pp = coconut.NewPP(newXs)
		}
		for i := range entriesToRemove {
			vks = append(vks[:i], vks[i+1:]...)
		}
	}

	if len(vks) >= c.cfg.Client.Threshold && len(vks) > 0 {
		if c.cfg.Client.Threshold > 0 && len(vks) != len(pp.Xs()) {
			return nil, c.logAndReturnError("handleReceivedVerificationKeys: Inconsistent response, vks: %v, pp: %v", len(vks), len(pp.Xs()))
		}
		c.log.Notice("Number of verification keys received is within threshold")
	} else {
		return nil, c.logAndReturnError("handleReceivedVerificationKeys: Received less than threshold number of verification keys")
	}

	// we only want threshold number of them, in future randomly choose them?
	if c.cfg.Client.Threshold > 0 {
		vks = vks[:c.cfg.Client.Threshold]
		pp = coconut.NewPP(pp.Xs()[:c.cfg.Client.Threshold])
	} else if (!c.cfg.Client.UseGRPC && len(vks) != len(c.cfg.Client.IAAddresses)) || (c.cfg.Client.UseGRPC && len(vks) != len(c.cfg.Client.IAgRPCAddresses)) {
		c.log.Error("No threshold, but obtained only %v out of %v verification keys", len(vks), len(c.cfg.Client.IAAddresses))
		c.log.Warning("This behaviour is currently undefined by requirements.")
		// should it continue regardless and assume the servers are down permanently or just terminate?
	}

	if shouldAggregate {
		avk := c.cryptoworker.CoconutWorker().AggregateVerificationKeysWrapper(vks, pp)
		c.log.Debugf("Aggregated %v verification keys (threshold: %v)", len(vks), c.cfg.Client.Threshold)

		return []*coconut.VerificationKey{avk}, nil
	}
	return vks, nil
}

// GetVerificationKeysGrpc sends GetVerificationKey request to all IA-grpc servers specified in the config.
// If the flag 'shouldAggregate' is set to true, the returned slice will consist of a single element,
// which will be the aggregated verification key.
// In the case of threshold system, first t results are aggregated, otherwise all results are aggregated.
// Error is returned if insufficient number of verification keys was received.
// TODO: correctly order results if shouldAggregate is false
func (c *Client) GetVerificationKeysGrpc(shouldAggregate bool) ([]*coconut.VerificationKey, error) {
	if !c.cfg.Client.UseGRPC {
		return nil, c.logAndReturnError(nonGRPCClientErr)
	}

	grpcDialOptions := c.defaultDialOptions
	isThreshold := c.cfg.Client.Threshold > 0

	verificationKeyRequest, err := commands.NewVerificationKeyRequest()
	if err != nil {
		return nil, c.logAndReturnError("GetVerificationKeysGrpc: Failed to create Vk request: %v", err)
	}

	c.log.Notice("Going to send GetVk request (via gRPCs) to %v IAs", len(c.cfg.Client.IAgRPCAddresses))
	responses := c.getGrpcResponses(grpcDialOptions, verificationKeyRequest)

	vks := make([]*coconut.VerificationKey, 0, len(c.cfg.Client.IAgRPCAddresses))
	xs := make([]*Curve.BIG, 0, len(c.cfg.Client.IAgRPCAddresses))

	for i := range responses {
		if responses[i] == nil {
			c.log.Error("nil response received")
			continue
		}
		vk, err := c.parseVkResponse(responses[i].Message.(*commands.VerificationKeyResponse))
		if err != nil {
			continue
		}
		vks = append(vks, vk)
		if isThreshold {
			xs = append(xs, Curve.NewBIGint(responses[i].ServerID))
		}
	}

	if c.cfg.Client.Threshold > 0 {
		return c.handleReceivedVerificationKeys(vks, coconut.NewPP(xs), shouldAggregate)
	}
	return c.handleReceivedVerificationKeys(vks, nil, shouldAggregate)
}

// GetVerificationKeys sends GetVerificationKey request to all IA servers specified in the config using TCP sockets.
// If the flag 'shouldAggregate' is set to true, the returned slice will consist of a single element,
// which will be the aggregated verification key.
// In the case of threshold system, first t results are aggregated, otherwise all results are aggregated.
// Error is returned if insufficient number of verification keys was received.
// TODO: correctly order results if shouldAggregate is false
func (c *Client) GetVerificationKeys(shouldAggregate bool) ([]*coconut.VerificationKey, error) {
	if c.cfg.Client.UseGRPC {
		return nil, c.logAndReturnError(gRPCClientErr)
	}

	cmd, err := commands.NewVerificationKeyRequest()
	if err != nil {
		return nil, c.logAndReturnError("GetVerificationKeys: Failed to create Vk request: %v", err)
	}

	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.GetVerificationKeyID)
	if packetBytes == nil {
		return nil, c.logAndReturnError("GetVerificationKeys: Could not create data packet for get verification key command")
	}
	c.log.Notice("Going to send GetVK request (via TCP socket) to %v IAs", len(c.cfg.Client.IAAddresses))

	responses := utils.GetServerResponses(
		packetBytes,
		c.cfg.Client.MaxRequests,
		c.log,
		c.cfg.Debug.ConnectTimeout,
		c.cfg.Debug.RequestTimeout,
		c.cfg.Client.IAAddresses,
		c.cfg.Client.IAIDs,
	)
	vks, pp := utils.ParseVerificationKeyResponses(responses, c.cfg.Client.Threshold > 0, c.log)
	return c.handleReceivedVerificationKeys(vks, pp, shouldAggregate)
}

// GetAggregateVerificationKeyGrpc is basically a wrapper for GetVerificationKeysGrpc,
// but returns a single vk rather than slice with one element.
func (c *Client) GetAggregateVerificationKeyGrpc() (*coconut.VerificationKey, error) {
	vks, err := c.GetVerificationKeysGrpc(true)
	if len(vks) == 1 && err == nil {
		return vks[0], nil
	}
	return nil, err
}

// GetAggregateVerificationKey is basically a wrapper for GetVerificationKeys,
// but returns a single vk rather than slice with one element.
func (c *Client) GetAggregateVerificationKey() (*coconut.VerificationKey, error) {
	vks, err := c.GetVerificationKeys(true)
	if len(vks) == 1 && err == nil {
		return vks[0], nil
	}
	return nil, err
}

// BlindSignAttributesGrpc sends blind sign request to all IA-grpc servers specified in the config
// with given set of public and private attributes.
// In the case of threshold system, after unblinding all results,
// first t results are aggregated and the result is randomized and returned.
// Otherwise all unblinded results are aggregated and then randomized.
// Error is returned if insufficient number of signatures was received.
func (c *Client) BlindSignAttributesGrpc(pubM []*Curve.BIG, privM []*Curve.BIG) (*coconut.Signature, error) {
	if !c.cfg.Client.UseGRPC {
		return nil, c.logAndReturnError(nonGRPCClientErr)
	}
	grpcDialOptions := c.defaultDialOptions
	isThreshold := c.cfg.Client.Threshold > 0

	if !coconut.ValidateBigSlice(pubM) || !coconut.ValidateBigSlice(privM) {
		return nil, c.logAndReturnError("BlindSignAttributesGrpc: invalid slice of attributes provided")
	}

	blindSignMats, err := c.cryptoworker.CoconutWorker().PrepareBlindSignWrapper(c.elGamalPublicKey, pubM, privM)
	if err != nil {
		return nil, c.logAndReturnError("BlindSignAttributesGrpc: Could not create blindSignMats: %v", err)
	}

	blindSignRequest, err := commands.NewBlindSignRequest(blindSignMats, c.elGamalPublicKey, pubM)
	if err != nil {
		return nil, c.logAndReturnError("BlindSignAttributesGrpc: Failed to create BlindSign request: %v", err)
	}

	c.log.Notice("Going to send Blind Sign request (via gRPCs) to %v IAs", len(c.cfg.Client.IAgRPCAddresses))
	responses := c.getGrpcResponses(grpcDialOptions, blindSignRequest)

	sigs := make([]*coconut.Signature, 0, len(c.cfg.Client.IAgRPCAddresses))
	xs := make([]*Curve.BIG, 0, len(c.cfg.Client.IAgRPCAddresses))

	for i := range responses {
		if responses[i] == nil {
			c.log.Error("nil response received")
			continue
		}
		sig, err := c.parseBlindSignResponse(responses[i].Message.(*commands.BlindSignResponse))
		if err != nil {
			continue
		}
		sigs = append(sigs, sig)
		if isThreshold {
			xs = append(xs, Curve.NewBIGint(responses[i].ServerID))
		}
	}
	if c.cfg.Client.Threshold > 0 {
		return c.handleReceivedSignatures(sigs, coconut.NewPP(xs))
	}
	return c.handleReceivedSignatures(sigs, nil)
}

// BlindSignAttributes sends sign request to all IA servers specified in the config
// using TCP sockets with given set of public and private attributes.
// In the case of threshold system, after unblinding all results,
// first t results are aggregated and the result is randomized and returned.
// Otherwise all unblinded results are aggregated and then randomized.
// Error is returned if insufficient number of signatures was received.
func (c *Client) BlindSignAttributes(pubM []*Curve.BIG, privM []*Curve.BIG) (*coconut.Signature, error) {
	if c.cfg.Client.UseGRPC {
		return nil, c.logAndReturnError(gRPCClientErr)
	}

	if !coconut.ValidateBigSlice(pubM) || !coconut.ValidateBigSlice(privM) {
		return nil, c.logAndReturnError("BlindSignAttributes: invalid slice of attributes provided")
	}

	blindSignMats, err := c.cryptoworker.CoconutWorker().PrepareBlindSignWrapper(c.elGamalPublicKey, pubM, privM)
	if err != nil {
		return nil, c.logAndReturnError("BlindSignAttributes: Could not create blindSignMats: %v", err)
	}

	cmd, err := commands.NewBlindSignRequest(blindSignMats, c.elGamalPublicKey, pubM)
	if err != nil {
		return nil, c.logAndReturnError("BlindSignAttributes: Failed to create BlindSign request: %v", err)
	}

	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.BlindSignID)
	if packetBytes == nil {
		return nil, c.logAndReturnError("BlindSignAttributes: Could not create data packet for blind sign command")
	}

	c.log.Notice("Going to send Blind Sign request to %v IAs", len(c.cfg.Client.IAAddresses))

	responses := utils.GetServerResponses(
		packetBytes,
		c.cfg.Client.MaxRequests,
		c.log,
		c.cfg.Debug.ConnectTimeout,
		c.cfg.Debug.RequestTimeout,
		c.cfg.Client.IAAddresses,
		c.cfg.Client.IAIDs,
	)
	sigs, pp := c.parseSignatureServerResponses(responses, c.cfg.Client.Threshold > 0, true)
	return c.handleReceivedSignatures(sigs, pp)
}

// SendCredentialsForVerificationGrpc sends a gRPC request to verify obtained credentials to some specified provider server.
// errcheck is ignored to make it not complain about not checking for err in conn.Close()
// nolint: lll, errcheck
func (c *Client) SendCredentialsForVerificationGrpc(pubM []*Curve.BIG, sig *coconut.Signature, addr string) (bool, error) {
	if !c.cfg.Client.UseGRPC {
		return false, c.logAndReturnError(nonGRPCClientErr)
	}
	grpcDialOptions := c.defaultDialOptions
	verifyRequest, err := commands.NewVerifyRequest(pubM, sig)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForVerificationGrpc: Failed to create Verify request: %v", err)
	}

	c.log.Debugf("Dialing %v", addr)
	conn, err := grpc.Dial(addr, grpcDialOptions...)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForVerificationGrpc: Could not dial %v (%v)", addr, err)
	}
	defer conn.Close()
	cc := pb.NewProviderClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(c.cfg.Debug.ConnectTimeout))
	defer cancel()

	r, err := cc.VerifyCredentials(ctx, verifyRequest)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForVerificationGrpc: Failed to receive response to verification request: %v", err)
	} else if r.GetStatus().Code != int32(commands.StatusCode_OK) {
		return false, c.logAndReturnError(
			"SendCredentialsForVerificationGrpc: Received invalid response with status: %v. Error: %v",
			r.GetStatus().Code,
			r.GetStatus().Message,
		)
	}
	return r.GetIsValid(), nil
}

// SendCredentialsForVerification sends a TCP request to verify obtained credentials to some specified provider server.
// nolint: lll
func (c *Client) SendCredentialsForVerification(pubM []*Curve.BIG, sig *coconut.Signature, addr string) (bool, error) {
	if c.cfg.Client.UseGRPC {
		return false, c.logAndReturnError(gRPCClientErr)
	}
	cmd, err := commands.NewVerifyRequest(pubM, sig)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForVerification: Failed to create Verify request: %v", err)
	}
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.VerifyID)
	if packetBytes == nil {
		return false, c.logAndReturnError("Could not create data packet for verify command")
	}

	c.log.Debugf("Dialing %v", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForVerification: Could not dial %v (%v)", addr, err)
	}

	// currently will never be thrown since there is no writedeadline
	if _, werr := conn.Write(packetBytes); werr != nil {
		return false, c.logAndReturnError("SendCredentialsForVerification: Failed to write to connection: %v", werr)
	}

	sderr := conn.SetReadDeadline(time.Now().Add(time.Duration(c.cfg.Debug.ConnectTimeout) * time.Millisecond))
	if sderr != nil {
		return false, c.logAndReturnError("SendCredentialsForVerification: Failed to set read deadline for connection: %v", sderr)
	}

	respPacket, err := utils.ReadPacketFromConn(conn)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForVerification: Received invalid response from %v: %v", addr, err)
	}

	verifyResponse := &commands.VerifyResponse{}
	if err := proto.Unmarshal(respPacket.Payload(), verifyResponse); err != nil {
		return false, c.logAndReturnError("SendCredentialsForVerification: Failed to recover verification result: %v", err)
	} else if verifyResponse.GetStatus().Code != int32(commands.StatusCode_OK) {
		return false, c.logAndReturnError(
			"SendCredentialsForVerification: Received invalid response with status: %v. Error: %v",
			verifyResponse.GetStatus().Code,
			verifyResponse.GetStatus().Message,
		)
	}

	return verifyResponse.IsValid, nil
}

func (c *Client) parseBlindVerifyResponse(packetResponse *packet.Packet) (bool, error) {
	blindVerifyResponse := &commands.BlindVerifyResponse{}
	if err := proto.Unmarshal(packetResponse.Payload(), blindVerifyResponse); err != nil {
		return false, c.logAndReturnError("parseBlindVerifyResponse: Failed to recover verification result: %v", err)
	} else if blindVerifyResponse.GetStatus().Code != int32(commands.StatusCode_OK) {
		return false, c.logAndReturnError(
			"parseBlindVerifyResponse: Received invalid response with status: %v. Error: %v",
			blindVerifyResponse.GetStatus().Code,
			blindVerifyResponse.GetStatus().Message,
		)
	}
	return blindVerifyResponse.IsValid, nil
}

// nolint: lll
func (c *Client) prepareBlindVerifyRequest(pubM []*Curve.BIG, privM []*Curve.BIG, sig *coconut.Signature, vk *coconut.VerificationKey) (*commands.BlindVerifyRequest, error) {
	var err error
	if vk == nil {
		if c.cfg.Client.UseGRPC {
			vk, err = c.GetAggregateVerificationKeyGrpc()
		} else {
			vk, err = c.GetAggregateVerificationKey()
		}
		if err != nil {
			return nil, c.logAndReturnError("prepareBlindVerifyRequest: Could not obtain aggregate verification key required to create proofs for verification: %v", err)
		}
	}

	blindShowMats, err := c.cryptoworker.CoconutWorker().ShowBlindSignatureWrapper(vk, sig, privM)
	if err != nil {
		return nil, c.logAndReturnError("prepareBlindVerifyRequest: Failed when creating proofs for verification: %v", err)
	}

	blindVerifyRequest, err := commands.NewBlindVerifyRequest(blindShowMats, sig, pubM)
	if err != nil {
		return nil, c.logAndReturnError("prepareBlindVerifyRequest: Failed to create BlindVerify request: %v", err)
	}
	return blindVerifyRequest, nil
}

// SendCredentialsForBlindVerificationGrpc sends a gRPC request to verify obtained blind credentials to some specified provider server.
// If client does not provide aggregate verification key, the call will first try to obtain it.
// errcheck is ignored to make it not complain about not checking for err in conn.Close()
// nolint: lll, errcheck
func (c *Client) SendCredentialsForBlindVerificationGrpc(pubM []*Curve.BIG, privM []*Curve.BIG, sig *coconut.Signature, addr string, vk *coconut.VerificationKey) (bool, error) {
	if !c.cfg.Client.UseGRPC {
		return false, c.logAndReturnError(nonGRPCClientErr)
	}
	grpcDialOptions := c.defaultDialOptions
	blindVerifyRequest, err := c.prepareBlindVerifyRequest(pubM, privM, sig, vk)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForBlindVerificationGrpc: Failed to prepare blindverifyrequest: %v", err)
	}

	c.log.Debugf("Dialing %v", addr)
	conn, err := grpc.Dial(addr, grpcDialOptions...)
	if err != nil {
		c.log.Errorf("Could not dial %v (%v)", addr, err)
	}
	defer conn.Close()
	cc := pb.NewProviderClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(c.cfg.Debug.ConnectTimeout))
	defer cancel()

	r, err := cc.BlindVerifyCredentials(ctx, blindVerifyRequest)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForBlindVerificationGrpc: Failed to receive response to verification request: %v", err)
	} else if r.GetStatus().Code != int32(commands.StatusCode_OK) {
		return false, c.logAndReturnError(
			"SendCredentialsForBlindVerificationGrpc: Received invalid response with status: %v. Error: %v",
			r.GetStatus().Code,
			r.GetStatus().Message,
		)
	}
	return r.GetIsValid(), nil
}

// SendCredentialsForBlindVerification sends a TCP request to verify obtained blind credentials to some specified provider server.
// If client does not provide aggregate verification key, the call will first try to obtain it.
// nolint: lll
func (c *Client) SendCredentialsForBlindVerification(pubM []*Curve.BIG, privM []*Curve.BIG, sig *coconut.Signature, addr string, vk *coconut.VerificationKey) (bool, error) {
	if c.cfg.Client.UseGRPC {
		return false, c.logAndReturnError(gRPCClientErr)
	}
	blindVerifyRequest, err := c.prepareBlindVerifyRequest(pubM, privM, sig, vk)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForBlindVerification: Failed to prepare blindverifyrequest: %v", err)
	}

	packetBytes := utils.CommandToMarshaledPacket(blindVerifyRequest, commands.BlindVerifyID)
	if packetBytes == nil {
		return false, c.logAndReturnError("Could not create data packet for blind verify command")
	}

	c.log.Debugf("Dialing %v", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForBlindVerification: Could not dial %v (%v)", addr, err)
	}

	// currently will never be thrown since there is no writedeadline
	if _, werr := conn.Write(packetBytes); werr != nil {
		return false, c.logAndReturnError("SendCredentialsForBlindVerification: Failed to write to connection: %v", werr)
	}

	sderr := conn.SetReadDeadline(time.Now().Add(time.Duration(c.cfg.Debug.ConnectTimeout) * time.Millisecond))
	if sderr != nil {
		return false, c.logAndReturnError("SendCredentialsForBlindVerification: Failed to set read deadline for connection: %v", sderr)
	}

	resp, err := utils.ReadPacketFromConn(conn)
	if err != nil {
		return false, c.logAndReturnError("SendCredentialsForBlindVerification: Received invalid response from %v: %v", addr, err)
	}
	return c.parseBlindVerifyResponse(resp)
}

func (c *Client) logAndReturnError(fmtString string, a ...interface{}) error {
	errstr := fmtString
	if a != nil {
		errstr = fmt.Sprintf(fmtString, a...)
	}
	c.log.Error(errstr)
	return errors.New(errstr)
}

// Stop stops client instance
func (c *Client) Stop() {
	c.log.Notice("Starting graceful shutdown.")
	c.cryptoworker.Halt()
	c.log.Notice("Shutdown complete.")
}

// New returns a new Client instance parameterized with the specified configuration.
// nolint: lll, gocyclo
func New(cfg *config.Config) (*Client, error) {
	// there is no need to further validate it, as if it's not nil, it was already done
	if cfg == nil {
		return nil, errors.New("Nil config provided")
	}

	log, err := logger.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a logger: %v", err)
	}
	clientLog := log.GetLogger("Client")
	clientLog.Noticef("Logging level set to %v", cfg.Logging.Level)

	G := bpgroup.New()
	elGamalPrivateKey := &elgamal.PrivateKey{}
	elGamalPublicKey := &elgamal.PublicKey{}

	if cfg.Debug.RegenerateKeys || !cfg.Client.PersistentKeys {
		clientLog.Notice("Generating new coconut-specific ElGamal keypair")
		elGamalPrivateKey, elGamalPublicKey = elgamal.Keygen(G)
		clientLog.Debug("Generated new keys")

		if cfg.Client.PersistentKeys {
			if err := elGamalPrivateKey.ToPEMFile(cfg.Client.PrivateKeyFile); err != nil {
				errstr := fmt.Sprintf("Couldn't write new keys (private key) to the files: %v", err)
				clientLog.Error(errstr)
				return nil, errors.New(errstr)
			}
			if cfg.Client.PublicKeyFile != "" {
				if err := elGamalPublicKey.ToPEMFile(cfg.Client.PublicKeyFile); err != nil {
					errstr := fmt.Sprintf("Couldn't write new keys (public key) to the files: %v", err)
					clientLog.Error(errstr)
					return nil, errors.New(errstr)
				}
			}
			clientLog.Notice("Written new keys to the files")
		}
	} else {
		// we must have a private key
		if _, err := os.Stat(cfg.Client.PrivateKeyFile); os.IsNotExist(err) {
			errstr := fmt.Sprintf("the config did not specify to regenerate the keys and the key file for the private key does not exist: %v", err)
			clientLog.Error(errstr)
			return nil, errors.New(errstr)
		}

		if err := elGamalPrivateKey.FromPEMFile(cfg.Client.PrivateKeyFile); err != nil {
			return nil, err
		}

		if cfg.Client.PublicKeyFile != "" {
			if _, err := os.Stat(cfg.Client.PublicKeyFile); os.IsNotExist(err) {
				errstr := fmt.Sprintf("the config did not specify to regenerate the keys and the key file for the public key does not exist: %v", err)
				clientLog.Error(errstr)
				return nil, errors.New(errstr)
			}
			if err := elGamalPublicKey.FromPEMFile(cfg.Client.PublicKeyFile); err != nil {
				return nil, err
			}
			// but it is possible to derive the public key if we recovered the private component
		} else {
			elGamalPublicKey = elgamal.PublicKeyFromPrivate(elGamalPrivateKey)
		}

		if !elGamalPublicKey.Gamma.Equals(Curve.G1mul(elGamalPublicKey.G, elGamalPrivateKey.D)) {
			clientLog.Error("Couldn't Load the keys")
			return nil, errors.New("The loaded keys were invalid. Delete the files and restart the server to regenerate them")
		}
		clientLog.Notice("Loaded Client's coconut-specific ElGamal keys from the files.")
	}

	params, err := coconut.Setup(cfg.Client.MaximumAttributes)
	if err != nil {
		return nil, errors.New("Error while generating params")
	}

	cryptoworker := cryptoworker.New(uint64(1), log, params, cfg.Debug.NumJobWorkers)
	clientLog.Notice("Started Coconut Worker")

	c := &Client{
		cfg: cfg,
		log: clientLog,

		elGamalPrivateKey: elGamalPrivateKey,
		elGamalPublicKey:  elGamalPublicKey,

		cryptoworker: cryptoworker,

		defaultDialOptions: []grpc.DialOption{
			grpc.WithInsecure(), // TODO: CERTS!!
		},
	}

	clientLog.Noticef("Created %v client", cfg.Client.Identifier)
	return c, nil
}
