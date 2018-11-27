package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jstuczyn/CoconutGo/client/config"
	"github.com/jstuczyn/CoconutGo/client/cryptoworker"
	"github.com/jstuczyn/CoconutGo/crypto/bpgroup"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/crypto/elgamal"
	"github.com/jstuczyn/CoconutGo/logger"
	pb "github.com/jstuczyn/CoconutGo/server/comm/grpc/services"
	"github.com/jstuczyn/CoconutGo/server/comm/utils"
	"github.com/jstuczyn/CoconutGo/server/commands"
	"github.com/jstuczyn/CoconutGo/server/packet"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"google.golang.org/grpc"
	"gopkg.in/op/go-logging.v1"
)

// todo: workers? look at what functionality is needed
// workers for crypto stuff.

// Client represents an user of a Coconut IA server
type Client struct {
	cfg *config.Config
	log *logging.Logger

	elGamalPrivateKey *elgamal.PrivateKey
	elGamalPublicKey  *elgamal.PublicKey

	cryptoworker *cryptoworker.Worker
}

var grpcDialOptions []grpc.DialOption

func (c *Client) writeRequestsToIAsToChannel(reqCh chan<- *utils.ServerRequest, data []byte) {
	for i := range c.cfg.Client.IAAddresses {
		c.log.Debug("Writing request to %v", c.cfg.Client.IAAddresses[i])
		reqCh <- &utils.ServerRequest{MarshaledData: data, ServerAddress: c.cfg.Client.IAAddresses[i], ServerID: c.cfg.Client.IAIDs[i]}
	}
}

func (c *Client) parseSignResponse(resp *commands.SignResponse) *coconut.Signature {
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

func (c *Client) parseSignatureResponses(responses []*utils.ServerResponse, isThreshold bool, isBlind bool) ([]*coconut.Signature, *coconut.PolynomialPoints) {
	// todo: possibly split sigs and blind sigs
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

			// todo: use parsesignresponses etc
			if err := proto.Unmarshal(responses[i].MarshaledData, resp); err != nil {
				c.log.Errorf("Failed to unmarshal response from: %v", responses[i].ServerAddress)
				continue
			}
			if resp.GetStatus().Code != int32(commands.StatusCode_OK) {
				c.log.Errorf("Received invalid response with status: %v. Error: %v", resp.GetStatus().Code, resp.GetStatus().Message)
				continue
			}
			var sig *coconut.Signature
			if isBlind {
				blindSig := &coconut.BlindedSignature{}
				if err := blindSig.FromProto(resp.(*commands.BlindSignResponse).Sig); err != nil {
					c.log.Errorf("Failed to unmarshal received signature from %v", responses[i].ServerAddress)
					continue // can still succeed with >= threshold sigs
				}
				sig = c.cryptoworker.CoconutWorker().UnblindWrapper(blindSig, c.elGamalPrivateKey)
			} else {
				sig = &coconut.Signature{}
				if err := sig.FromProto(resp.(*commands.SignResponse).Sig); err != nil {
					c.log.Errorf("Failed to unmarshal received signature from %v", responses[i].ServerAddress)
					continue // can still succeed with >= threshold sigs
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

	// just to check in test_main if outsigs are equal. next commit removes it
	rSig = aSig
	return rSig
}

// todo: like previous TCP methods, break that one down
func (c *Client) SignAttributes_grpc(pubM []*Curve.BIG) *coconut.Signature {
	isThreshold := c.cfg.Client.Threshold > 0

	maxRequests := c.cfg.Client.MaxRequests
	if c.cfg.Client.MaxRequests <= 0 {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

	signRequest, err := commands.NewSignRequest(pubM)
	if err != nil {
		c.log.Errorf("Failed to create Sign request: %v", err)
		return nil
	}

	c.log.Notice("Going to send Sign request (via gRPCs) to %v IAs", len(c.cfg.Client.IAgRPCAddresses))
	reqCh := make(chan struct {
		string
		int
	})

	allDone := make(chan struct{})
	sigs := make([]*coconut.Signature, 0, len(c.cfg.Client.IAgRPCAddresses))
	xs := make([]*Curve.BIG, 0, len(c.cfg.Client.IAgRPCAddresses))
	appendLock := &sync.Mutex{}

	for i := 0; i < maxRequests; i++ {
		go func() {
			for {
				req, ok := <-reqCh
				if !ok {
					return
				}
				c.log.Debugf("Dialing %v", req.string)
				conn, err := grpc.Dial(req.string, grpcDialOptions...)
				if err != nil {
					c.log.Errorf("Could not dial %v", req.string)
				}
				defer conn.Close()
				cc := pb.NewIssuerClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				r, err := cc.SignAttributes(ctx, signRequest)
				if err != nil {
					c.log.Errorf("Failed to obtain signature from %v, err: %v", req.string, err)
				} else {
					sig := c.parseSignResponse(r)
					var x *Curve.BIG
					if isThreshold {
						x = Curve.NewBIGint(req.int)
					}

					appendLock.Lock()
					sigs = append(sigs, sig)
					if isThreshold {
						xs = append(xs, x)
					}
					if len(sigs) == len(c.cfg.Client.IAgRPCAddresses) {
						close(allDone)
					}
					appendLock.Unlock()
				}
			}
		}()
	}

	for i, addr := range c.cfg.Client.IAgRPCAddresses {
		reqCh <- struct {
			string
			int
		}{addr, c.cfg.Client.IAIDs[i]}
	}

waitLoop:
	for {
		select {
		case <-allDone:
			c.log.Debug("Got responses from all servers")
			break waitLoop
		case <-time.After(time.Duration(c.cfg.Debug.RequestTimeout) * time.Millisecond):
			c.log.Notice("Timed out while sending requests")
			break waitLoop
		}
	}

	close(reqCh)

	if isThreshold {
		return c.handleReceivedSignatures(sigs, coconut.NewPP(xs))
	}
	return c.handleReceivedSignatures(sigs, nil)
}

func (c *Client) SignAttributes(pubM []*Curve.BIG) *coconut.Signature {
	maxRequests := c.cfg.Client.MaxRequests
	if c.cfg.Client.MaxRequests <= 0 {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

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

	var closeOnce sync.Once

	responses := make([]*utils.ServerResponse, len(c.cfg.Client.IAAddresses)) // can't possibly get more results
	respCh := make(chan *utils.ServerResponse)
	reqCh := utils.SendServerRequests(respCh, maxRequests, c.log, c.cfg.Debug.ConnectTimeout)

	// write requests in a goroutine so we wouldn't block when trying to read responses
	go func() {
		defer func() {
			// in case the channel unexpectedly blocks (which should THEORETICALLY not happen),
			// the client won't crash
			if r := recover(); r != nil {
				c.log.Critical("Recovered: %v", r)
			}
		}()
		c.writeRequestsToIAsToChannel(reqCh, packetBytes)
		closeOnce.Do(func() { close(reqCh) }) // to terminate the goroutines after they are done
	}()

	utils.WaitForServerResponses(respCh, responses, c.log, c.cfg.Debug.RequestTimeout)

	// in case something weird happened, like it threw an error somewhere or a timeout happened before all requests were sent.
	closeOnce.Do(func() { close(reqCh) })

	return c.handleReceivedSignatures(c.parseSignatureResponses(responses, c.cfg.Client.Threshold > 0, false))
}

// more for debug purposes to check if the signature verifies, but might also be useful if client wants to make local checks
// If it's going to aggregate results, it will return slice with a single element.
func (c *Client) GetVerificationKeys(shouldAggregate bool) []*coconut.VerificationKey {
	maxRequests := c.cfg.Client.MaxRequests
	if c.cfg.Client.MaxRequests <= 0 {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

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

	c.log.Notice("Going to send GetVK request to %v IAs", len(c.cfg.Client.IAAddresses))

	var closeOnce sync.Once

	responses := make([]*utils.ServerResponse, len(c.cfg.Client.IAAddresses)) // can't possibly get more results
	respCh := make(chan *utils.ServerResponse)
	reqCh := utils.SendServerRequests(respCh, maxRequests, c.log, c.cfg.Debug.ConnectTimeout)

	// write requests in a goroutine so we wouldn't block when trying to read responses
	go func() {
		defer func() {
			// in case the channel unexpectedly blocks (which should THEORETICALLY not happen),
			// the client won't crash
			if r := recover(); r != nil {
				c.log.Critical("Recovered: %v", r)
			}
		}()
		c.writeRequestsToIAsToChannel(reqCh, packetBytes)
		closeOnce.Do(func() { close(reqCh) }) // to terminate the goroutines after they are done
	}()
	utils.WaitForServerResponses(respCh, responses, c.log, c.cfg.Debug.RequestTimeout)

	// in case something weird happened, like it threw an error somewhere or a timeout happened before all requests were sent.
	closeOnce.Do(func() { close(reqCh) })

	vks, pp := utils.ParseVerificationKeyResponses(responses, c.cfg.Client.Threshold > 0, c.log)

	if len(vks) >= c.cfg.Client.Threshold && len(vks) > 0 {
		c.log.Notice("Number of verification keys received is within threshold")
	} else {
		c.log.Error("Received less than threshold number of verification keys")
		return nil
	}

	if shouldAggregate {
		vks = []*coconut.VerificationKey{c.cryptoworker.CoconutWorker().AggregateVerificationKeysWrapper(vks, pp)}
	}
	return vks
}

// basically a wrapper for GetVerificationKeys but returns a single vk rather than slice with one element
func (c *Client) GetAggregateVerificationKey() *coconut.VerificationKey {
	vks := c.GetVerificationKeys(true)
	if vks != nil && len(vks) == 1 {
		return vks[0]
	}
	return nil
}

func (c *Client) BlindSignAttributes(pubM []*Curve.BIG, privM []*Curve.BIG) *coconut.Signature {
	maxRequests := c.cfg.Client.MaxRequests
	if c.cfg.Client.MaxRequests <= 0 {

		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

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

	var closeOnce sync.Once

	responses := make([]*utils.ServerResponse, len(c.cfg.Client.IAAddresses)) // can't possibly get more results
	respCh := make(chan *utils.ServerResponse)
	reqCh := utils.SendServerRequests(respCh, maxRequests, c.log, c.cfg.Debug.ConnectTimeout)

	// write requests in a goroutine so we wouldn't block when trying to read responses
	go func() {
		defer func() {
			// in case the channel unexpectedly blocks (which should THEORETICALLY not happen),
			// the client won't crash
			if r := recover(); r != nil {
				c.log.Critical("Recovered: %v", r)
			}
		}()
		c.writeRequestsToIAsToChannel(reqCh, packetBytes)
		closeOnce.Do(func() { close(reqCh) }) // to terminate the goroutines after they are done
	}()

	utils.WaitForServerResponses(respCh, responses, c.log, c.cfg.Debug.RequestTimeout)

	// in case something weird happened, like it threw an error somewhere or a timeout happened before all requests were sent.
	closeOnce.Do(func() { close(reqCh) })

	sigs, pp := c.parseSignatureResponses(responses, c.cfg.Client.Threshold > 0, true)

	if len(sigs) >= c.cfg.Client.Threshold && len(sigs) > 0 {
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

func (c *Client) parseVerifyResponse(packetResponse *packet.Packet) bool {
	verifyResponse := &commands.VerifyResponse{}
	if err := proto.Unmarshal(packetResponse.Payload(), verifyResponse); err != nil {
		c.log.Errorf("Failed to recover verification result: %v", err)
		return false
	}
	return verifyResponse.IsValid
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

func (c *Client) SendDummy(msg string) {
	// in our case no point in keeping the connection alive as we will only send at most couple of rpcs per epoch
	conn, err := grpc.Dial("127.0.0.1:5000", grpc.WithInsecure())
	if err != nil {
		c.log.Fatal(err)
	}
	defer conn.Close()
	cc := pb.NewIssuerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := cc.DummyRpc(ctx, &pb.DummyRequest{Hello: "Hello"})
	if err != nil {
		c.log.Fatal(err)
	}
	c.log.Fatalf("%v %v", r.Echo, r.World)
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
	}

	// todo: timeouts etc
	grpcDialOptions = []grpc.DialOption{
		grpc.WithInsecure(),
	}

	clientLog.Noticef("Created %v client", cfg.Client.Identifier)
	return c, nil
}
