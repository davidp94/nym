package client

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jstuczyn/CoconutGo/constants"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/server/commands"
	"github.com/jstuczyn/CoconutGo/server/packet"

	"github.com/jstuczyn/CoconutGo/client/config"
	"github.com/jstuczyn/CoconutGo/crypto/bpgroup"
	"github.com/jstuczyn/CoconutGo/logger"

	"github.com/jstuczyn/CoconutGo/crypto/elgamal"

	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"gopkg.in/op/go-logging.v1"
)

// todo: workers? look at what functionality is needed

// Client represents an user of a Coconut IA server
type Client struct {
	cfg *config.Config

	log *logging.Logger

	params *coconut.Params

	elGamalPrivateKey *elgamal.PrivateKey
	elGamalPublicKey  *elgamal.PublicKey
}

// todo: think about what is going to be used down the line and consider using interface{} instead for channels

// all we receive are either vk/sigs/blindsigs and all of them require ID (if treshold is used)
type response struct {
	marshaledObj []byte
	serverID     int // will be needed for threshold aggregation
}

type request struct {
	addr     string
	serverID int
}

// will be replaced/modified once whole thing is changed to use protobuf
func createDataPacket(cmd commands.Command, cmdID commands.CommandID) []byte {
	payloadBytes, err := cmd.MarshalBinary()
	if err != nil {
		return nil
	}
	rawCmd := commands.NewRawCommand(cmdID, payloadBytes)
	cmdBytes := rawCmd.ToBytes()

	packetIn := packet.NewPacket(cmdBytes)
	packetBytes, err := packetIn.MarshalBinary()
	if err != nil {
		return nil
	}
	return packetBytes
}

func readResponse(conn net.Conn) (*packet.Packet, error) {
	var err error
	tmp := make([]byte, 4) // packetlength
	if _, err = io.ReadFull(conn, tmp); err != nil {
		return nil, err
	}
	packetOutLength := binary.BigEndian.Uint32(tmp)
	packetOutBytes := make([]byte, packetOutLength)
	copy(packetOutBytes, tmp)
	if _, err = io.ReadFull(conn, packetOutBytes[4:]); err != nil {
		return nil, err
	}
	return packet.FromBytes(packetOutBytes), nil
}

func (c *Client) sendRequests(packetBytes []byte, respCh chan<- response) chan<- request {
	var maxRequests int
	if c.cfg.Client.MaxRequests > 0 {
		maxRequests = c.cfg.Client.MaxRequests
	} else {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

	ch := make(chan request)
	for i := 0; i < maxRequests; i++ {
		go func() {
			for {
				req, ok := <-ch
				if !ok {
					return
				}

				c.log.Debugf("Dialing %v", req.addr)
				conn, err := net.Dial("tcp", req.addr)
				if err != nil {
					c.log.Errorf("Could not dial %v", req.addr)
					return
				}

				conn.Write(packetBytes)
				conn.SetReadDeadline(time.Now().Add(time.Duration(c.cfg.Debug.ConnectTimeout) * time.Millisecond))

				resp, err := readResponse(conn)
				if err != nil {
					c.log.Errorf("Received invalid response from %v: %v", req.addr, err)
					return
				} else {
					respCh <- response{marshaledObj: resp.Payload(), serverID: req.serverID}
				}
			}
		}()
	}
	return ch
}

func (c *Client) waitForResponses(respCh <-chan response, responses []response) {
	i := 0
	for {
		select {
		case resp := <-respCh:
			c.log.Debug("Received a reply from IA")
			responses[i] = resp
			i++

			if i == len(c.cfg.Client.IAAddresses) {
				c.log.Debug("Got responses from all servers")
				return
			}
		case <-time.After(time.Duration(c.cfg.Debug.RequestTimeout) * time.Millisecond):
			c.log.Notice("Timed out while sending sign requests")
			return
		}
	}
}

func (c *Client) writeRequestsToChannel(reqCh chan<- request) {
	for i := range c.cfg.Client.IAAddresses {
		c.log.Debug("Writing request to %v", c.cfg.Client.IAAddresses[i])
		reqCh <- request{addr: c.cfg.Client.IAAddresses[i], serverID: c.cfg.Client.IAIDs[i]}
	}
}

func (c *Client) sendSignRequests(pubM []*Curve.BIG, respCh chan<- response) chan<- request {
	cmd := commands.NewSign(pubM)
	packetBytes := createDataPacket(cmd, commands.SignID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return nil
	}
	return c.sendRequests(packetBytes, respCh)
}

func parseSignatures(responses []response, isThreshold bool) ([]*coconut.Signature, *coconut.PolynomialPoints) {
	validSigs := 0
	for i := range responses {
		if len(responses[i].marshaledObj) == 2*constants.ECPLen {
			validSigs++
		}
	}
	sigs := make([]*coconut.Signature, validSigs)
	xs := make([]*Curve.BIG, validSigs)

	j := 0
	for i := range responses {
		if len(responses[i].marshaledObj) == 2*constants.ECPLen {
			sig := &coconut.Signature{}
			if sig.UnmarshalBinary(responses[i].marshaledObj) != nil {
				return nil, nil
			}
			sigs[j] = sig
			if isThreshold {
				xs[j] = Curve.NewBIGint(responses[i].serverID) // no point in computing that if we won't need it
			}
			j++
		}
	}
	if isThreshold {
		return sigs, coconut.NewPP(xs)
	} else {
		return sigs, nil
	}
}

func (c *Client) SignAttributes(pubM []*Curve.BIG) *coconut.Signature {
	c.log.Notice("Going to send Sign request to %v IAs", len(c.cfg.Client.IAAddresses))

	var closeOnce sync.Once

	responses := make([]response, len(c.cfg.Client.IAAddresses)) // can't possibly get more results
	respCh := make(chan response)
	reqCh := c.sendSignRequests(pubM, respCh)

	// write requests in a goroutine so we wouldn't block when trying to read responses
	go func() {
		c.writeRequestsToChannel(reqCh)
		closeOnce.Do(func() { close(reqCh) }) // to terminate the goroutines after they are done
	}()

	c.waitForResponses(respCh, responses)

	// in case something weird happened, like it threw an error somewhere or a timeout happened before all requests were sent.
	closeOnce.Do(func() { close(reqCh) })

	sigs, pp := parseSignatures(responses, c.cfg.Client.Threshold > 0)

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

func parseVerificationKeys(responses []response, isThreshold bool) ([]*coconut.VerificationKey, *coconut.PolynomialPoints) {
	validVks := 0
	for i := range responses {
		if len(responses[i].marshaledObj) >= 3*constants.ECP2Len { // each vk has to have AT LEAST 3 G2 elems
			validVks++
		}
	}
	vks := make([]*coconut.VerificationKey, validVks)
	xs := make([]*Curve.BIG, validVks)

	j := 0
	for i := range responses {
		if len(responses[i].marshaledObj) >= 3*constants.ECP2Len {
			vk := &coconut.VerificationKey{}
			if vk.UnmarshalBinary(responses[i].marshaledObj) != nil {
				return nil, nil
			}
			vks[j] = vk
			if isThreshold {
				xs[j] = Curve.NewBIGint(responses[i].serverID) // no point in computing that if we won't need it
			}
			j++
		}
	}
	if isThreshold {
		return vks, coconut.NewPP(xs)
	} else {
		return vks, nil
	}
}

func (c *Client) sendVKRequests(respCh chan<- response) chan<- request {
	cmd := commands.NewVk()
	packetBytes := createDataPacket(cmd, commands.GetVerificationKeyID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return nil
	}
	return c.sendRequests(packetBytes, respCh)
}

// more for debug purposes to check if the signature verifies, but might also be useful if client wants to make local checks
// If it's going to aggregate results, it will return slice with a single element.
func (c *Client) GetVerificationKeys(shouldAggregate bool) []*coconut.VerificationKey {
	c.log.Notice("Going to send GetVK request to %v IAs", len(c.cfg.Client.IAAddresses))

	var closeOnce sync.Once

	responses := make([]response, len(c.cfg.Client.IAAddresses)) // can't possibly get more results
	respCh := make(chan response)
	reqCh := c.sendVKRequests(respCh)

	// write requests in a goroutine so we wouldn't block when trying to read responses
	go func() {
		c.writeRequestsToChannel(reqCh)
		closeOnce.Do(func() { close(reqCh) }) // to terminate the goroutines after they are done
	}()

	c.waitForResponses(respCh, responses)

	// in case something weird happened, like it threw an error somewhere or a timeout happened before all requests were sent.
	closeOnce.Do(func() { close(reqCh) })

	vks, pp := parseVerificationKeys(responses, c.cfg.Client.Threshold > 0)

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
	} else {
		return nil
	}
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
