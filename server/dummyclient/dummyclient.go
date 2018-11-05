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
	"gopkg.in/op/go-logging.v1"
)

const addr = "127.0.0.1:4000"

var clientLog *logging.Logger

func init() {
	log := logger.New()
	clientLog = log.GetLogger("Client")
}

func getSignature() {
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

	conn, _ := net.Dial("tcp", "127.0.0.1:4000")
	clientLog.Critical("writing sign cmd")
	conn.Write(packet)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	resLen := 2 * constants.ECPLen // we expect signature which is of that length
	// listen for reply
	signatureBytes := make([]byte, resLen)
	var err error
	if _, err = io.ReadFull(conn, signatureBytes); err != nil {
		panic(err)
	}
	sig := &coconut.Signature{}
	err = sig.UnmarshalBinary(signatureBytes)
	if err == nil {
		clientLog.Notice("Successfuly obtained signature", utils.ToCoconutString(sig.Sig1()), utils.ToCoconutString(sig.Sig2()))
	}
}

func getVks() {
	payload := commands.Vk{}
	payloadBytes, _ := payload.MarshalBinary()
	rawCmd := commands.NewRawCommand(commands.GetVerificationKeyID, payloadBytes)
	cmdBytes := rawCmd.ToBytes()

	packet := make([]byte, 4+len(cmdBytes))
	binary.BigEndian.PutUint32(packet, uint32(len(cmdBytes)))
	copy(packet[4:], cmdBytes)

	conn, _ := net.Dial("tcp", "127.0.0.1:4000")
	clientLog.Critical("writing vk cmd")
	conn.Write(packet)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var err error

	tmp := make([]byte, 4)
	if _, err = io.ReadFull(conn, tmp); err != nil {
		panic(err)
	}
	resLen := binary.BigEndian.Uint32(tmp)

	vkBytes := make([]byte, resLen)
	if _, err = io.ReadFull(conn, vkBytes); err != nil {
		panic(err)
	}
	vk := &coconut.VerificationKey{}
	err = vk.UnmarshalBinary(vkBytes)
	if err == nil {
		clientLog.Notice("Successfuly obtained vk")
		clientLog.Notice(utils.ToCoconutString(vk.G2()))
		clientLog.Notice(utils.ToCoconutString(vk.Alpha()))
		for i := range vk.Beta() {
			clientLog.Notice(utils.ToCoconutString(vk.Beta()[i]))
		}
	}

	// we dont know how long the response is going to be, so first lets get length

}

func main() {
	// getSignature()
	// time.Sleep(time.Second * 3)
	getVks()
}
