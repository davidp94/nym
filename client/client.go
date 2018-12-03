package client

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/client/config"
	"0xacab.org/jstuczyn/CoconutGo/client/cryptoworker"
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

// todo: deal with bunch of duplicate code in multiple _grpc methods

// Client represents an user of a Coconut IA server
type Client struct {
	cfg *config.Config
	log *logging.Logger

	elGamalPrivateKey *elgamal.PrivateKey
	elGamalPublicKey  *elgamal.PublicKey

	cryptoworker       *cryptoworker.Worker
	defaultDialOptions []grpc.DialOption
}

func (c *Client) parseGetVkResponse(resp *commands.VerificationKeyResponse) *coconut.VerificationKey {
	if resp == nil {
		c.log.Error("Received respons was nil")
		return nil
	}
	if resp.GetStatus().Code != int32(commands.StatusCode_OK) {
		c.log.Errorf("Received invalid response with status: %v. Error: %v", resp.GetStatus().Code, resp.GetStatus().Message)
		return nil
	}
	vk := &coconut.VerificationKey{}
	if err := vk.FromProto(resp.Vk); err != nil {
		c.log.Errorf("Failed to unmarshal received verification key")
		return nil
	}
	return vk
}

func (c *Client) parseSignResponse(resp *commands.SignResponse) *coconut.Signature {
	if resp == nil {
		c.log.Error("Received respons was nil")
		return nil
	}
	if resp.GetStatus().Code != int32(commands.StatusCode_OK) {
		c.log.Errorf("Received invalid response with status: %v. Error: %v", resp.GetStatus().Code, resp.GetStatus().Message)
		return nil
	}
	sig := &coconut.Signature{}
	if err := sig.FromProto(resp.Sig); err != nil {
		c.log.Errorf("Failed to unmarshal received signature")
		return nil
	}
	return sig
}

func (c *Client) parseBlindSignResponse(resp *commands.BlindSignResponse) *coconut.Signature {
	if resp == nil {
		c.log.Error("Received respons was nil")
		return nil
	}
	if resp.GetStatus().Code != int32(commands.StatusCode_OK) {
		c.log.Errorf("Received invalid response with status: %v. Error: %v", resp.GetStatus().Code, resp.GetStatus().Message)
		return nil
	}
	blindSig := &coconut.BlindedSignature{}
	if err := blindSig.FromProto(resp.Sig); err != nil {
		c.log.Errorf("Failed to unmarshal received signature")
		return nil
	}
	return c.cryptoworker.CoconutWorker().UnblindWrapper(blindSig, c.elGamalPrivateKey)
}

func (c *Client) getGrpcResponses(grpcDialOptions []grpc.DialOption, request proto.Message) []*utils.ServerResponse_grpc {
	responses := make([]*utils.ServerResponse_grpc, len(c.cfg.Client.IAgRPCAddresses))
	respCh := make(chan *utils.ServerResponse_grpc)
	reqCh, cancelFuncs := c.sendGRPCs(respCh, grpcDialOptions)

	go func() {
		for i := range c.cfg.Client.IAgRPCAddresses {
			c.log.Debug("Writing request to %v", c.cfg.Client.IAgRPCAddresses[i])
			reqCh <- &utils.ServerRequest_grpc{Message: request, ServerAddress: c.cfg.Client.IAgRPCAddresses[i], ServerID: c.cfg.Client.IAIDs[i]}
		}
	}()

	c.waitForGrpcResponses(respCh, responses, cancelFuncs)
	close(reqCh)
	return responses
}

func (c *Client) waitForGrpcResponses(respCh <-chan *utils.ServerResponse_grpc, responses []*utils.ServerResponse_grpc, cancelFuncs []context.CancelFunc) {
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

// it's not in utils as in principle servers should never create grpcs; only reply to them
func (c *Client) sendGRPCs(respCh chan<- *utils.ServerResponse_grpc, dialOptions []grpc.DialOption) (chan<- *utils.ServerRequest_grpc, []context.CancelFunc) {
	reqCh := make(chan *utils.ServerRequest_grpc)

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
					c.log.Errorf("Could not dial %v", req.ServerAddress)
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
					c.log.Fatal("NOT IMPLEMENTED YET")
				}
				if errgrpc != nil {
					c.log.Errorf("Failed to obtain signature from %v, err: %v", req.ServerAddress, err)
				} else {
					respCh <- &utils.ServerResponse_grpc{Message: resp, ServerID: req.ServerID, ServerAddress: req.ServerAddress}
				}
			}
		}(i)
	}
	return reqCh, cancelFuncs
}

func (c *Client) parseSignatureServerResponses(responses []*utils.ServerResponse, isThreshold bool, isBlind bool) ([]*coconut.Signature, *coconut.PolynomialPoints) {
	sigs := make([]*coconut.Signature, 0, len(responses))
	xs := make([]*Curve.BIG, 0, len(responses))
	for i := range responses {
		if responses[i] != nil {
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
			if isBlind {
				if sig = c.parseBlindSignResponse(resp.(*commands.BlindSignResponse)); sig == nil {
					continue
				}
			} else {
				if sig = c.parseSignResponse(resp.(*commands.SignResponse)); sig == nil {
					continue
				}
			}

			sigs = append(sigs, sig)
			if isThreshold {
				xs = append(xs, Curve.NewBIGint(responses[i].ServerID))
			}
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

func (c *Client) handleReceivedSignatures(sigs []*coconut.Signature, pp *coconut.PolynomialPoints) *coconut.Signature {
	if len(sigs) >= c.cfg.Client.Threshold && len(sigs) > 0 {
		if len(sigs) != len(pp.Xs()) {
			c.log.Errorf("Inconsistent response, sigs: %v, pp: %v\n", len(sigs), len(pp.Xs()))
			return nil
		}
		c.log.Notice("Number of signatures received is within threshold")
	} else {
		c.log.Error("Received less than threshold number of signatures")
		return nil
	}

	// we only want threshold number of them, in future randomly choose them?
	if c.cfg.Client.Threshold > 0 {
		sigs = sigs[:c.cfg.Client.Threshold]
		pp = coconut.NewPP(pp.Xs()[:c.cfg.Client.Threshold])
	} else if len(sigs) != len(c.cfg.Client.IAAddresses) {
		c.log.Error("No threshold, but obtained only %v out of %v signatures", len(sigs), len(c.cfg.Client.IAAddresses))
		// should it continue regardless and assume the servers are down pernamently or just terminate?
	}

	aSig := c.cryptoworker.CoconutWorker().AggregateSignaturesWrapper(sigs, pp)
	c.log.Debugf("Aggregated %v signatures (threshold: %v)", len(sigs), c.cfg.Client.Threshold)

	rSig := c.cryptoworker.CoconutWorker().RandomizeWrapper(aSig)
	c.log.Debug("Randomized the signature")

	return rSig
}

func (c *Client) SignAttributes_grpc(pubM []*Curve.BIG) *coconut.Signature {
	grpcDialOptions := c.defaultDialOptions
	isThreshold := c.cfg.Client.Threshold > 0

	signRequest, err := commands.NewSignRequest(pubM)
	if err != nil {
		c.log.Errorf("Failed to create Sign request: %v", err)
		return nil
	}

	c.log.Notice("Going to send Sign request (via gRPCs) to %v IAs", len(c.cfg.Client.IAgRPCAddresses))
	responses := c.getGrpcResponses(grpcDialOptions, signRequest)

	sigs := make([]*coconut.Signature, 0, len(c.cfg.Client.IAgRPCAddresses))
	xs := make([]*Curve.BIG, 0, len(c.cfg.Client.IAgRPCAddresses))

	for i := range responses {
		sigs = append(sigs, c.parseSignResponse(responses[i].Message.(*commands.SignResponse)))
		if isThreshold {
			xs = append(xs, Curve.NewBIGint(responses[i].ServerID))
		}
	}
	return c.handleReceivedSignatures(sigs, coconut.NewPP(xs))
}

func (c *Client) SignAttributes(pubM []*Curve.BIG) *coconut.Signature {
	cmd, err := commands.NewSignRequest(pubM)
	if err != nil {
		c.log.Errorf("Failed to create Sign request: %v", err)
		return nil
	}
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.SignID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return nil
	}

	c.log.Notice("Going to send Sign request (via TCP socket) to %v IAs", len(c.cfg.Client.IAAddresses))
	responses := utils.GetServerResponses(packetBytes, c.cfg.Client.MaxRequests, c.log, c.cfg.Debug.ConnectTimeout, c.cfg.Debug.RequestTimeout, c.cfg.Client.IAAddresses, c.cfg.Client.IAIDs)
	return c.handleReceivedSignatures(c.parseSignatureServerResponses(responses, c.cfg.Client.Threshold > 0, false))
}

func (c *Client) handleReceivedVerificationKeys(vks []*coconut.VerificationKey, pp *coconut.PolynomialPoints, shouldAggregate bool) []*coconut.VerificationKey {
	if len(vks) >= c.cfg.Client.Threshold && len(vks) > 0 {
		if len(vks) != len(pp.Xs()) {
			c.log.Errorf("Inconsistent response, vks: %v, pp: %v\n", len(vks), len(pp.Xs()))
			return nil
		}
		c.log.Notice("Number of verification keys received is within threshold")
	} else {
		c.log.Error("Received less than threshold number of verification keys")
		return nil
	}

	// we only want threshold number of them, in future randomly choose them?
	if c.cfg.Client.Threshold > 0 {
		vks = vks[:c.cfg.Client.Threshold]
		pp = coconut.NewPP(pp.Xs()[:c.cfg.Client.Threshold])
	} else if len(vks) != len(c.cfg.Client.IAAddresses) {
		c.log.Error("No threshold, but obtained only %v out of %v verification keys", len(vks), len(c.cfg.Client.IAAddresses))
		// should it continue regardless and assume the servers are down pernamently or just terminate?
	}

	if shouldAggregate {
		avk := c.cryptoworker.CoconutWorker().AggregateVerificationKeysWrapper(vks, pp)
		c.log.Debugf("Aggregated %v verification keys (threshold: %v)", len(vks), c.cfg.Client.Threshold)

		return []*coconut.VerificationKey{avk}
	}
	return vks
}

func (c *Client) GetVerificationKeys_grpc(shouldAggregate bool) []*coconut.VerificationKey {
	grpcDialOptions := c.defaultDialOptions
	isThreshold := c.cfg.Client.Threshold > 0

	verificationKeyRequest, err := commands.NewVerificationKeyRequest()
	if err != nil {
		c.log.Errorf("Failed to create Vk request: %v", err)
		return nil
	}

	c.log.Notice("Going to send GetVk request (via gRPCs) to %v IAs", len(c.cfg.Client.IAgRPCAddresses))
	responses := c.getGrpcResponses(grpcDialOptions, verificationKeyRequest)

	vks := make([]*coconut.VerificationKey, 0, len(c.cfg.Client.IAgRPCAddresses))
	xs := make([]*Curve.BIG, 0, len(c.cfg.Client.IAgRPCAddresses))

	for i := range responses {
		vks = append(vks, c.parseGetVkResponse(responses[i].Message.(*commands.VerificationKeyResponse)))
		if isThreshold {
			xs = append(xs, Curve.NewBIGint(responses[i].ServerID))
		}
	}
	return c.handleReceivedVerificationKeys(vks, coconut.NewPP(xs), shouldAggregate)
}

// If it's going to aggregate results, it will return slice with a single element.
func (c *Client) GetVerificationKeys(shouldAggregate bool) []*coconut.VerificationKey {
	cmd, err := commands.NewVerificationKeyRequest()
	if err != nil {
		c.log.Errorf("Failed to create Vk request: %v", err)
		return nil
	}
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.GetVerificationKeyID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return nil
	}
	c.log.Notice("Going to send GetVK request (via TCP socket) to %v IAs", len(c.cfg.Client.IAAddresses))

	responses := utils.GetServerResponses(packetBytes, c.cfg.Client.MaxRequests, c.log, c.cfg.Debug.ConnectTimeout, c.cfg.Debug.RequestTimeout, c.cfg.Client.IAAddresses, c.cfg.Client.IAIDs)
	vks, pp := utils.ParseVerificationKeyResponses(responses, c.cfg.Client.Threshold > 0, c.log)
	return c.handleReceivedVerificationKeys(vks, pp, shouldAggregate)

}

// basically a wrapper for GetVerificationKeys but returns a single vk rather than slice with one element
func (c *Client) GetAggregateVerificationKey_grpc() *coconut.VerificationKey {
	vks := c.GetVerificationKeys_grpc(true)
	if vks != nil && len(vks) == 1 {
		return vks[0]
	}
	return nil
}

// basically a wrapper for GetVerificationKeys but returns a single vk rather than slice with one element
func (c *Client) GetAggregateVerificationKey() *coconut.VerificationKey {
	vks := c.GetVerificationKeys(true)
	if vks != nil && len(vks) == 1 {
		return vks[0]
	}
	return nil
}

// todo: so much repeating code with SignAttributes_grpc
func (c *Client) BlindSignAttributes_grpc(pubM []*Curve.BIG, privM []*Curve.BIG) *coconut.Signature {
	grpcDialOptions := c.defaultDialOptions
	isThreshold := c.cfg.Client.Threshold > 0

	blindSignMats, err := c.cryptoworker.CoconutWorker().PrepareBlindSignWrapper(c.elGamalPublicKey, pubM, privM)
	if err != nil {
		c.log.Errorf("Could not create blindSignMats: %v", err)
		return nil
	}

	blindSignRequest, err := commands.NewBlindSignRequest(blindSignMats, c.elGamalPublicKey, pubM)
	if err != nil {
		c.log.Errorf("Failed to create BlindSign request: %v", err)
		return nil
	}

	c.log.Notice("Going to send Blind Sign request (via gRPCs) to %v IAs", len(c.cfg.Client.IAgRPCAddresses))
	responses := c.getGrpcResponses(grpcDialOptions, blindSignRequest)

	sigs := make([]*coconut.Signature, 0, len(c.cfg.Client.IAgRPCAddresses))
	xs := make([]*Curve.BIG, 0, len(c.cfg.Client.IAgRPCAddresses))

	for i := range responses {
		sigs = append(sigs, c.parseBlindSignResponse(responses[i].Message.(*commands.BlindSignResponse)))
		if isThreshold {
			xs = append(xs, Curve.NewBIGint(responses[i].ServerID))
		}
	}
	return c.handleReceivedSignatures(sigs, coconut.NewPP(xs))
}

func (c *Client) BlindSignAttributes(pubM []*Curve.BIG, privM []*Curve.BIG) *coconut.Signature {
	blindSignMats, err := c.cryptoworker.CoconutWorker().PrepareBlindSignWrapper(c.elGamalPublicKey, pubM, privM)
	if err != nil {
		c.log.Errorf("Could not create blindSignMats: %v", err)
		return nil
	}

	cmd, err := commands.NewBlindSignRequest(blindSignMats, c.elGamalPublicKey, pubM)
	if err != nil {
		c.log.Errorf("Failed to create BlindSign request: %v", err)
		return nil
	}
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.BlindSignID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return nil
	}

	c.log.Notice("Going to send Blind Sign request to %v IAs", len(c.cfg.Client.IAAddresses))

	responses := utils.GetServerResponses(packetBytes, c.cfg.Client.MaxRequests, c.log, c.cfg.Debug.ConnectTimeout, c.cfg.Debug.RequestTimeout, c.cfg.Client.IAAddresses, c.cfg.Client.IAIDs)
	sigs, pp := c.parseSignatureServerResponses(responses, c.cfg.Client.Threshold > 0, true)
	return c.handleReceivedSignatures(sigs, pp)
}

func (c *Client) parseVerifyResponse(packetResponse *packet.Packet) bool {
	verifyResponse := &commands.VerifyResponse{}
	if err := proto.Unmarshal(packetResponse.Payload(), verifyResponse); err != nil {
		c.log.Errorf("Failed to recover verification result: %v", err)
		return false
	}
	return verifyResponse.IsValid
}

func (c *Client) SendCredentialsForVerification_grpc(pubM []*Curve.BIG, sig *coconut.Signature, addr string) bool {
	grpcDialOptions := c.defaultDialOptions

	verifyRequest, err := commands.NewVerifyRequest(pubM, sig)
	if err != nil {
		c.log.Errorf("Failed to create Verify request: %v", err)
		return false
	}

	c.log.Debugf("Dialing %v", addr)
	conn, err := grpc.Dial(addr, grpcDialOptions...)
	if err != nil {
		c.log.Errorf("Could not dial %v", addr)
	}
	defer conn.Close()
	cc := pb.NewProviderClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(c.cfg.Debug.ConnectTimeout))
	defer cancel()

	r, err := cc.VerifyCredentials(ctx, verifyRequest)
	if err != nil {
		c.log.Errorf("Failed to receive response to verification request: %v", err)
		return false
	} else if r.GetStatus().Code != int32(commands.StatusCode_OK) {
		c.log.Errorf("Received invalid response with status: %v. Error: %v", r.GetStatus().Code, r.GetStatus().Message)
		return false
	}
	return r.GetIsValid()
}

// depends on future API in regards of type of servers response
func (c *Client) SendCredentialsForVerification(pubM []*Curve.BIG, sig *coconut.Signature, addr string) bool {
	cmd, err := commands.NewVerifyRequest(pubM, sig)
	if err != nil {
		c.log.Errorf("Failed to create Verify request: %v", err)
		return false
	}
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.VerifyID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return false
	}

	c.log.Debugf("Dialing %v", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		c.log.Errorf("Could not dial %v", addr)
		return false
	}

	conn.Write(packetBytes)
	conn.SetReadDeadline(time.Now().Add(time.Duration(c.cfg.Debug.ConnectTimeout) * time.Millisecond))

	resp, err := utils.ReadPacketFromConn(conn)
	if err != nil {
		c.log.Errorf("Received invalid response from %v: %v", addr, err)
	}
	return c.parseVerifyResponse(resp)
}

func (c *Client) parseBlindVerifyResponse(packetResponse *packet.Packet) bool {
	blindVerifyResponse := &commands.BlindVerifyResponse{}
	if err := proto.Unmarshal(packetResponse.Payload(), blindVerifyResponse); err != nil {
		c.log.Errorf("Failed to recover verification result: %v", err)
		return false
	}
	return blindVerifyResponse.IsValid
}

// todo: code nearly identical to public verification...
func (c *Client) SendCredentialsForBlindVerification_grpc(pubM []*Curve.BIG, privM []*Curve.BIG, sig *coconut.Signature, addr string, vk *coconut.VerificationKey) bool {
	grpcDialOptions := c.defaultDialOptions

	if vk == nil {
		vk = c.GetAggregateVerificationKey_grpc()
		if vk == nil {
			c.log.Error("Could not obtain aggregate verification key required to create proofs for verification")
			return false
		}
	}

	blindShowMats, err := c.cryptoworker.CoconutWorker().ShowBlindSignatureWrapper(vk, sig, privM)
	if err != nil {
		c.log.Errorf("Failed when creating proofs for verification: %v", err)
		return false
	}

	blindVerifyRequest, err := commands.NewBlindVerifyRequest(blindShowMats, sig, pubM)
	if err != nil {
		c.log.Errorf("Failed to create BlindVerify request: %v", err)
		return false
	}

	c.log.Debugf("Dialing %v", addr)
	conn, err := grpc.Dial(addr, grpcDialOptions...)
	if err != nil {
		c.log.Errorf("Could not dial %v", addr)
	}
	defer conn.Close()
	cc := pb.NewProviderClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(c.cfg.Debug.ConnectTimeout))
	defer cancel()

	r, err := cc.BlindVerifyCredentials(ctx, blindVerifyRequest)
	if err != nil {
		c.log.Errorf("Failed to receive response to verification request: %v", err)
		return false
	} else if r.GetStatus().Code != int32(commands.StatusCode_OK) {
		c.log.Errorf("Received invalid response with status: %v. Error: %v", r.GetStatus().Code, r.GetStatus().Message)
		return false
	}
	return r.GetIsValid()
}

// depends on future API in regards of type of servers response
// if vk is nil, first the client will try to obtain it
func (c *Client) SendCredentialsForBlindVerification(pubM []*Curve.BIG, privM []*Curve.BIG, sig *coconut.Signature, addr string, vk *coconut.VerificationKey) bool {
	if vk == nil {
		vk = c.GetAggregateVerificationKey()
		if vk == nil {
			c.log.Error("Could not obtain aggregate verification key required to create proofs for verification")
			return false
		}
	}

	blindShowMats, err := c.cryptoworker.CoconutWorker().ShowBlindSignatureWrapper(vk, sig, privM)
	if err != nil {
		c.log.Errorf("Failed when creating proofs for verification: %v", err)
		return false
	}

	cmd, err := commands.NewBlindVerifyRequest(blindShowMats, sig, pubM)
	if err != nil {
		c.log.Errorf("Failed to create BlindVerify request: %v", err)
		return false
	}
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.BlindVerifyID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return false
	}

	c.log.Debugf("Dialing %v", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		c.log.Errorf("Could not dial %v", addr)
		return false
	}

	conn.Write(packetBytes)
	conn.SetReadDeadline(time.Now().Add(time.Duration(c.cfg.Debug.ConnectTimeout) * time.Millisecond))

	resp, err := utils.ReadPacketFromConn(conn)
	return c.parseBlindVerifyResponse(resp)
}

// Stop stops client instance
func (c *Client) Stop() {
	c.log.Notice("Starting graceful shutdown.")
	c.cryptoworker.Halt()
	c.log.Notice("Shutdown complete.")
}

// New returns a new Client instance parameterized with the specified configuration.
func New(cfg *config.Config) (*Client, error) {
	var err error
	// todo: config for client to put this in
	log := logger.New("", "DEBUG", false)
	if log == nil {
		return nil, errors.New("Failed to create a logger")
	}
	clientLog := log.GetLogger("Client")
	// ensures that it IS displayed if any logging at all is enabled
	clientLog.Critical("Logging level set to %v", cfg.Logging.Level)

	G := bpgroup.New()
	elGamalPrivateKey := &elgamal.PrivateKey{}
	elGamalPublicKey := &elgamal.PublicKey{}

	// todo: allow for empty public key if private key is set
	if cfg.Debug.RegenerateKeys || !cfg.Client.PersistentKeys {
		clientLog.Notice("Generating new coconut-specific ElGamal keypair")
		elGamalPrivateKey, elGamalPublicKey = elgamal.Keygen(G)
		clientLog.Debug("Generated new keys")

		if cfg.Client.PersistentKeys {
			if elGamalPrivateKey.ToPEMFile(cfg.Client.PrivateKeyFile) != nil || elGamalPublicKey.ToPEMFile(cfg.Client.PublicKeyFile) != nil {
				clientLog.Error("Couldn't write new keys to the files")
				return nil, errors.New("Couldn't write new keys to the files")
			}
			clientLog.Notice("Written new keys to the files")
		}
	} else {
		if _, err := os.Stat(cfg.Client.PrivateKeyFile); os.IsNotExist(err) {
			return nil, errors.New("The config did not specify to regenerate the keys and the files do not exist.")
		}
		if _, err := os.Stat(cfg.Client.PublicKeyFile); os.IsNotExist(err) {
			return nil, errors.New("The config did not specify to regenerate the keys and the files do not exist.")
		}

		err = elGamalPrivateKey.FromPEMFile(cfg.Client.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		err = elGamalPublicKey.FromPEMFile(cfg.Client.PublicKeyFile)
		if err != nil {
			return nil, err
		}
		if !elGamalPublicKey.Gamma.Equals(Curve.G1mul(elGamalPublicKey.G, elGamalPrivateKey.D)) {
			clientLog.Errorf("Couldn't Load the keys")
			return nil, errors.New("The loaded keys were invalid. Delete the files and restart the server to regenerate them")
		}
		clientLog.Notice("Loaded Client's coconut-specific ElGamal keys from the files.")
	}

	params, err := coconut.Setup(cfg.Client.MaximumAttributes)
	if err != nil {
		return nil, errors.New("Error while generating params")
	}

	cryptoworker := cryptoworker.New(uint64(1), log, params, cfg.Debug.NumJobWorkers)
	clientLog.Noticef("Started Coconut Worker")

	c := &Client{
		cfg: cfg,
		log: clientLog,

		elGamalPrivateKey: elGamalPrivateKey,
		elGamalPublicKey:  elGamalPublicKey,

		cryptoworker: cryptoworker,

		// todo: timeouts etc
		defaultDialOptions: []grpc.DialOption{
			grpc.WithInsecure(), // TODO: CERTS!!
		},
	}

	clientLog.Noticef("Created %v client", cfg.Client.Identifier)
	return c, nil
}
