package main

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/utils"

	"net"

	"github.com/jstuczyn/CoconutGo/crypto/bpgroup"
	"github.com/jstuczyn/CoconutGo/logger"
	"github.com/jstuczyn/CoconutGo/server/commands"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const addr = "127.0.0.1:4000"

func main() {
	log := logger.New()
	clientLog := log.GetLogger("Client")
	conn, _ := net.Dial("tcp", "127.0.0.1:4000")
	// make a sign request command
	G := bpgroup.New()

	pubM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}
	payload := commands.NewSign(pubM)
	payloadBytes, _ := payload.MarshalBinary()
	rawCmd := commands.NewRawCommand(commands.SignID, payloadBytes)
	cmdBytes := rawCmd.ToBytes()

	packet := make([]byte, 4+len(cmdBytes))
	binary.BigEndian.PutUint32(packet, uint32(len(cmdBytes)))
	copy(packet[4:], cmdBytes)

	clientLog.Critical("writing cmd")
	conn.Write(packet)

	// if client doesnt close socket then server hangs?
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	resLen := 2 * constants.ECPLen // we expect signature which is of that length
	// listen for reply
	signatureBytes := make([]byte, resLen)
	var err error
	if _, err = io.ReadFull(conn, signatureBytes); err != nil {
		clientLog.Critical(string(signatureBytes))
		panic(err)
	}
	sig := &coconut.Signature{}
	err = sig.UnmarshalBinary(signatureBytes)
	if err == nil {
		clientLog.Notice("Successfuly obtained signature", utils.ToCoconutString(sig.Sig1()), utils.ToCoconutString(sig.Sig2()))
	}
}
