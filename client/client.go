package client

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/jstuczyn/CoconutGo/server/comm/utils"

	"github.com/jstuczyn/CoconutGo/constants"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/server/commands"

	"github.com/jstuczyn/CoconutGo/client/config"
	"github.com/jstuczyn/CoconutGo/crypto/bpgroup"
	"github.com/jstuczyn/CoconutGo/logger"

	"github.com/jstuczyn/CoconutGo/crypto/elgamal"

	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"gopkg.in/op/go-logging.v1"
)

// todo: workers? look at what functionality is needed
// workers for crypto stuff.

// Client represents an user of a Coconut IA server
type Client struct {
	cfg *config.Config

	log *logging.Logger

	params *coconut.Params

	elGamalPrivateKey *elgamal.PrivateKey
	elGamalPublicKey  *elgamal.PublicKey
}

func (c *Client) writeRequestsToIAsToChannel(reqCh chan<- *utils.ServerRequest, data []byte) {
	for i := range c.cfg.Client.IAAddresses {
		c.log.Debug("Writing request to %v", c.cfg.Client.IAAddresses[i])
		reqCh <- &utils.ServerRequest{MarshaledData: data, ServerAddress: c.cfg.Client.IAAddresses[i], ServerID: c.cfg.Client.IAIDs[i]}
	}
}

func (c *Client) parseSignatureResponses(responses []*utils.ServerResponse, isThreshold bool, isBlind bool) ([]*coconut.Signature, *coconut.PolynomialPoints) {
	expectedResponseLength := 2 * constants.ECPLen
	if isBlind {
		expectedResponseLength += constants.ECPLen
	}
	validSigs := 0
	for i := range responses {
		// first check guarantees we will be able to check second expression without memory violation
		if responses[i] != nil && len(responses[i].MarshaledData) == expectedResponseLength {
			validSigs++
		}
	}
	sigs := make([]*coconut.Signature, validSigs)
	xs := make([]*Curve.BIG, validSigs)

	j := 0
	for i := range responses {
		if responses[i] != nil && len(responses[i].MarshaledData) == expectedResponseLength {
			sig := &coconut.Signature{}
			if isBlind {
				blindedSig := &coconut.BlindedSignature{}
				if blindedSig.UnmarshalBinary(responses[i].MarshaledData) != nil {
					return nil, nil
				}
				sig = coconut.Unblind(c.params, blindedSig, c.elGamalPrivateKey)
			} else {
				if sig.UnmarshalBinary(responses[i].MarshaledData) != nil {
					return nil, nil
				}
			}
			sigs[j] = sig
			if isThreshold {
				xs[j] = Curve.NewBIGint(responses[i].ServerID) // no point in computing that if we won't need it
			}
			j++
		}
	}
	if isThreshold {
		return sigs, coconut.NewPP(xs)
	}
	return sigs, nil

}

func (c *Client) SignAttributes(pubM []*Curve.BIG) *coconut.Signature {
	maxRequests := c.cfg.Client.MaxRequests
	if c.cfg.Client.MaxRequests <= 0 {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

	cmd := commands.NewSign(pubM)
	packetBytes := utils.CommandToMarshaledPacket(cmd, commands.SignID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return nil
	}

	c.log.Notice("Going to send Sign request to %v IAs", len(c.cfg.Client.IAAddresses))

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

	sigs, pp := c.parseSignatureResponses(responses, c.cfg.Client.Threshold > 0, false)

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

	aSig := coconut.AggregateSignatures(c.params, sigs, pp)
	c.log.Debugf("Aggregated %v signatures (threshold: %v)", len(sigs), c.cfg.Client.Threshold)

	rSig := coconut.Randomize(c.params, aSig)
	c.log.Debug("Randomized the signature")

	return rSig
}

// more for debug purposes to check if the signature verifies, but might also be useful if client wants to make local checks
// If it's going to aggregate results, it will return slice with a single element.
func (c *Client) GetVerificationKeys(shouldAggregate bool) []*coconut.VerificationKey {
	maxRequests := c.cfg.Client.MaxRequests
	if c.cfg.Client.MaxRequests <= 0 {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

	cmd := commands.NewVk()
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

	vks, pp := utils.ParseVerificationKeyResponses(responses, c.cfg.Client.Threshold > 0)

	if len(vks) >= c.cfg.Client.Threshold && len(vks) > 0 {
		c.log.Notice("Number of verification keys received is within threshold")
	} else {
		c.log.Error("Received less than threshold number of verification keys")
		return nil
	}

	if shouldAggregate {
		vks = []*coconut.VerificationKey{coconut.AggregateVerificationKeys(c.params, vks, pp)}
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

func (c *Client) BlindSignAttributes(privM []*Curve.BIG, pubM []*Curve.BIG) *coconut.Signature {
	maxRequests := c.cfg.Client.MaxRequests
	if c.cfg.Client.MaxRequests <= 0 {

		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

	blindSignMats, err := coconut.PrepareBlindSign(c.params, c.elGamalPublicKey, pubM, privM)
	if err != nil {
		c.log.Errorf("Could not create blindSignMats: %v", err)
		return nil
	}

	cmd := commands.NewBlindSign(blindSignMats, c.elGamalPublicKey, pubM)
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

	aSig := coconut.AggregateSignatures(c.params, sigs, pp)
	c.log.Debugf("Aggregated %v signatures (threshold: %v)", len(sigs), c.cfg.Client.Threshold)

	rSig := coconut.Randomize(c.params, aSig)
	c.log.Debug("Randomized the signature")

	return rSig
}

// depends on future API in regards of type of servers response
func (c *Client) SendCredentialsForVerification(pubM []*Curve.BIG, sig *coconut.Signature, addr string) bool {
	cmd := commands.NewVerify(pubM, sig)
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
	c.log.Notice("%v", resp)
	if err != nil {
		c.log.Errorf("Received invalid response from %v: %v", addr, err)
	} else if resp.Payload()[0] == 1 {
		return true
	}
	return false
}

// depends on future API in regards of type of servers response
func (c *Client) SendCredentialsForBlindVerification() bool {
	return false
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

	// todo: if worker then make mux params
	params, err := coconut.Setup(cfg.Client.MaximumAttributes)
	if err != nil {
		return nil, errors.New("Error while generating params")
	}

	c := &Client{
		cfg: cfg,
		log: clientLog,

		elGamalPrivateKey: elGamalPrivateKey,
		elGamalPublicKey:  elGamalPublicKey,

		params: params,
	}

	clientLog.Noticef("Created %v client", cfg.Client.Identifier)
	return c, nil
}
