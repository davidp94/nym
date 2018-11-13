package client

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

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

type signResponse struct {
	sig      *coconut.Signature
	serverID int // will be needed for threshold aggregation
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

func (c *Client) sendSignRequests(pubM []*Curve.BIG, sigCh chan<- signResponse, maxRequests int) chan<- request {
	ch := make(chan request)
	cmd := commands.NewSign(pubM)
	packetBytes := createDataPacket(cmd, commands.SignID)
	if packetBytes == nil {
		c.log.Error("Could not create data packet")
		return nil
	}
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
					sig := &coconut.Signature{}
					if err := sig.UnmarshalBinary(resp.Payload()); err != nil {
						c.log.Errorf("Received invalid response from %v: %v", req.addr, err)
					} else {
						sigCh <- signResponse{sig: sig, serverID: req.serverID}
					}
				}
			}
		}()
	}
	return ch
}

// returns slice with threshold number of signatures, if threshold = 0, then get all of them
func getThresholdNumberOfSignatures(sigs []signResponse, threshold int) ([]*coconut.Signature, *coconut.PolynomialPoints) {
	var count int
	if threshold > 0 {
		count = threshold
	} else {
		count = countValidSigs(sigs)
	}

	sigsOut := make([]*coconut.Signature, count)
	xs := make([]*Curve.BIG, count)

	j := 0
	for i := range sigs {
		if sigs[i].sig != nil {
			sigsOut[j] = sigs[i].sig
			if threshold > 0 {
				xs[j] = Curve.NewBIGint(sigs[i].serverID)
			}
			j++
		}
		if j+1 == count {
			if threshold > 0 {
				return sigsOut, coconut.NewPP(xs)
			} else {
				return sigsOut, nil
			}
		}
	}
	// never reached because we know there is at least threshold number of 'valid' signatures
	return nil, nil
}

func countValidSigs(sigs []signResponse) int {
	count := 0
	for i := range sigs {
		if sigs[i].sig != nil {
			count++
		}
	}
	return count
}

func (c *Client) SignAttributes(pubM []*Curve.BIG) *coconut.Signature {
	var closeOnce sync.Once

	var maxRequests int
	if c.cfg.Client.MaxRequests > 0 {
		maxRequests = c.cfg.Client.MaxRequests
	} else {
		maxRequests = 16 // virtually no limit for our needs, but in case there's a bug somewhere it wouldn't destroy it all.
	}

	sigResps := make([]signResponse, 0, len(c.cfg.Client.IAAddresses))
	sigs := make(chan signResponse)
	sendCh := c.sendSignRequests(pubM, sigs, maxRequests)

	// write requests in a goroutine so we wouldn't block when trying to read responses
	go func() {
		for i := range c.cfg.Client.IAAddresses {
			c.log.Debug("Sending sign request to %v", c.cfg.Client.IAAddresses[i])
			sendCh <- request{addr: c.cfg.Client.IAAddresses[i], serverID: c.cfg.Client.IAIDs[i]}
		}
		closeOnce.Do(func() { close(sendCh) }) // to terminate the goroutines after they are done
	}()

waitloop:
	for {
		select {
		case sigResp := <-sigs: // do we care about order of signatures or learn in case some server fails, which one?
			c.log.Debug("Received a reply from IA")
			if sigResp.sig == nil {
				c.log.Error("Empty signature")
			} else {
				sigResps = append(sigResps, sigResp)
			}
			if countValidSigs(sigResps) == len(c.cfg.Client.IAAddresses) {
				c.log.Debug("Got valid responses from all servers")
				break waitloop
			}
		case <-time.After(time.Duration(c.cfg.Debug.RequestTimeout) * time.Millisecond):
			c.log.Notice("Timed out while sending sign requests")
			nonNil := countValidSigs(sigResps)
			if nonNil >= c.cfg.Client.Threshold {
				c.log.Notice("Number of signatures received is within threshold")
				break waitloop
			} else {
				c.log.Error("Received less than threshold number of signatures")
				return nil
			}
		}
	}

	// in case something weird happened, like it threw and error somewhere it timeout happened before all requests were sent.
	closeOnce.Do(func() { close(sendCh) })

	thresholdSigs, pp := getThresholdNumberOfSignatures(sigResps, c.cfg.Client.Threshold)

	c.log.Debugf("Aggregated %v signatures", c.cfg.Client.Threshold)
	aSig := coconut.AggregateSignatures(c.params, thresholdSigs, pp)
	rSig := coconut.Randomize(c.params, aSig)

	return rSig
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
