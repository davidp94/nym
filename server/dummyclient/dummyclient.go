package main

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/jstuczyn/CoconutGo/constants"
	"github.com/jstuczyn/CoconutGo/crypto/elgamal"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/utils"

	"net"

	"github.com/jstuczyn/CoconutGo/logger"
	"github.com/jstuczyn/CoconutGo/server/commands"
	"github.com/jstuczyn/CoconutGo/server/packet"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
	"gopkg.in/op/go-logging.v1"
)

const addr = "127.0.0.1:4000"

var clientLog *logging.Logger

func init() {
	log := logger.New()
	clientLog = log.GetLogger("Client")
}

func makeAndSendPacket(cmd commands.Command, cmdID commands.CommandID) *packet.Packet {
	payloadBytes, _ := cmd.MarshalBinary()
	rawCmd := commands.NewRawCommand(cmdID, payloadBytes)
	cmdBytes := rawCmd.ToBytes()

	packetIn := packet.NewPacket(cmdBytes)
	packetBytes, err := packetIn.MarshalBinary()
	if err != nil {
		return nil
	}

	conn, _ := net.Dial("tcp", addr)
	clientLog.Noticef("writing %d cmd", int(cmdID))
	conn.Write(packetBytes)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	tmp := make([]byte, 4) // packetlength
	if _, err = io.ReadFull(conn, tmp); err != nil {
		panic(err)
	}
	packetOutLength := binary.BigEndian.Uint32(tmp)
	packetOutBytes := make([]byte, packetOutLength)
	copy(packetOutBytes, tmp)
	if _, err = io.ReadFull(conn, packetOutBytes[4:]); err != nil {
		panic(err)
	}
	return packet.FromBytes(packetOutBytes)
}

func getSignature(pubM []*Curve.BIG) *coconut.Signature {
	cmd := commands.NewSign(pubM)
	resp := makeAndSendPacket(cmd, commands.SignID)

	sig := &coconut.Signature{}
	err := sig.UnmarshalBinary(resp.Payload())
	if err == nil {
		clientLog.Notice("Successfuly obtained signature", utils.ToCoconutString(sig.Sig1()), utils.ToCoconutString(sig.Sig2()))
	}
	return sig
}

func getVks() *coconut.VerificationKey {
	cmd := &commands.Vk{}
	resp := makeAndSendPacket(cmd, commands.GetVerificationKeyID)

	vk := &coconut.VerificationKey{}
	err := vk.UnmarshalBinary(resp.Payload())
	if err == nil {
		clientLog.Notice("Successfuly obtained vk")
		clientLog.Notice(utils.ToCoconutString(vk.G2()))
		clientLog.Notice(utils.ToCoconutString(vk.Alpha()))
		for i := range vk.Beta() {
			clientLog.Notice(utils.ToCoconutString(vk.Beta()[i]))
		}
	}
	return vk
}

func verify(pubM []*Curve.BIG, sig *coconut.Signature) bool {
	cmd := commands.NewVerify(pubM, sig)
	resp := makeAndSendPacket(cmd, commands.VerifyID)
	if resp.Payload()[0] == 0 {
		return false
	}
	return true
}

func blindSign(blindSignMats *coconut.BlindSignMats, gamma *Curve.ECP, pubM []*Curve.BIG) *coconut.BlindedSignature {
	cmd := commands.NewBlindSign(blindSignMats, gamma, pubM)
	resp := makeAndSendPacket(cmd, commands.BlindSignID)

	sig := &coconut.BlindedSignature{}
	err := sig.UnmarshalBinary(resp.Payload())
	if err == nil {
		clientLog.Notice("Successfuly obtained blind signature", utils.ToCoconutString(sig.Sig1()), utils.ToCoconutString(sig.Sig2Tilda().C1()), utils.ToCoconutString(sig.Sig2Tilda().C2()))
	}
	return sig
}

func main() {
	params, _ := coconut.Setup(constants.SetupAttrs)
	G := params.G
	pubM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}
	privM := []*Curve.BIG{Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng()), Curve.Randomnum(G.Order(), G.Rng())}
	d, gamma := elgamal.Keygen(G)
	blindSignMats, _ := coconut.PrepareBlindSign(params, gamma, pubM, privM)

	blindSig := blindSign(blindSignMats, gamma, pubM)
	sig := coconut.Unblind(params, blindSig, d)

	// sig := getSignature(pubM)
	// time.Sleep(time.Second * 3)
	// getVks()
	clientLog.Notice("Verify Result:", verify(append(privM, pubM...), sig)) // reveal all private attributes
}
