package main

import (
	"bufio"
	"encoding/binary"

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
	cmd := commands.NewCommand(commands.SignID, payloadBytes)
	cmdBytes := cmd.ToBytes()

	packet := make([]byte, 4+len(cmdBytes))
	binary.BigEndian.PutUint32(packet, uint32(len(cmdBytes)))
	copy(packet[4:], cmdBytes)

	clientLog.Critical("writing cmd")
	conn.Write(packet)

	// if client doesnt close socket then server hangs?
	// conn.Close()

	// listen for reply
	clientLog.Debug("before io")
	message, _ := bufio.NewReader(conn).ReadString('\n')
	clientLog.Notice("Message from server: " + message)
}
