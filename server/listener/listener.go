package listener

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jstuczyn/CoconutGo/logger"
	"github.com/jstuczyn/CoconutGo/server/commands"
	"github.com/jstuczyn/CoconutGo/server/packet"

	"github.com/jstuczyn/CoconutGo/worker"
	"gopkg.in/op/go-logging.v1"
)

// todo: add length to EVERY packet sent, even if it can be easily implied

// make it unexported like katzenpost? though it uses session which currently is not here
type Listener struct {
	sync.Mutex
	worker.Worker

	log *logging.Logger

	incomingCh chan<- interface{}
	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup

	l net.Listener

	id uint64
}

func (l *Listener) Halt() {
	l.l.Close()
	l.Worker.Halt()

	// currently nothing is using the channels or wg anyway.
	close(l.closeAllCh)
	l.closeAllWg.Wait()
}

func (l *Listener) worker() {
	addr := l.l.Addr()
	l.log.Noticef("Listening on: %v", addr)
	defer func() {
		l.log.Noticef("Stopping listening on: %v", addr)
		l.l.Close() // Usually redundant, but harmless.
	}()
	for {
		conn, err := l.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		tcpConn := conn.(*net.TCPConn)
		tcpConn.SetKeepAlive(true)
		// tcpConn.SetKeepAlivePeriod(constants.KeepAliveInterval)

		l.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

		l.onNewConn(conn)
	}
}

func (l *Listener) onNewConn(conn net.Conn) {
	// todo deadlines etc
	defer func() {
		l.log.Debug("Closing Connection")
		conn.Close()
	}()

	l.log.Debug("onNewConn called")
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	var err error
	tmp := make([]byte, 4) // packetlength
	if _, err = io.ReadFull(conn, tmp); err != nil {
		panic(err)
	}
	packetLength := binary.BigEndian.Uint32(tmp)
	packetBytes := make([]byte, packetLength)
	copy(packetBytes, tmp)
	if _, err = io.ReadFull(conn, packetBytes[4:]); err != nil {
		panic(err)
	}
	inPacket := packet.FromBytes(packetBytes) // currently rather redundant as we recover nothing useful, but might be needed when headers are expanded

	cmd := commands.FromBytes(inPacket.Payload())
	resCh := make(chan interface{}, 1)
	cmdReq := commands.NewCommandRequest(cmd, resCh)

	l.incomingCh <- cmdReq
	outPacket := l.resolveCommand(resCh)
	l.replyToClient(outPacket, conn)
}

func (l *Listener) replyToClient(packet *packet.Packet, conn net.Conn) {
	l.log.Notice("Replying back to the client")
	b, err := packet.MarshalBinary()
	if err == nil {
		conn.Write(b)
	} else {
		l.log.Error("Couldn't reply to the client") // conn will close regardless after this
	}
}

func (l *Listener) resolveCommand(resCh chan interface{}) *packet.Packet {
	res := <-resCh

	var payload []byte
	switch resVal := res.(type) {
	case encoding.BinaryMarshaler: // all coconut structures implement that interface
		l.log.Debug("Received non-empty response from the worker")
		b, err := resVal.MarshalBinary()
		if err == nil {
			payload = b
		}
	default:
		l.log.Error("Failed to resolve command")
	}
	return packet.NewPacket(payload)
}

// case *coconut.Signature:
// 	l.log.Debug("Received signature from the worker")
// 	b, err := resVal.MarshalBinary()
// 	if err == nil {
// 		payload = b
// 	}
// case *coconut.VerificationKey:
// 	l.log.Debug("Received VK fron the worker")
// 	b, err := resVal.MarshalBinary()
// 	if err == nil {
// 		l.log.Notice("Writing VK response to the client")
// 		conn.Write(packet)
// 	}

// New creates a new listener.
func New(incomingCh chan<- interface{}, id uint64, l *logger.Logger, addr string) (*Listener, error) {
	var err error

	listener := &Listener{
		incomingCh: incomingCh,
		closeAllCh: make(chan interface{}),
		log:        l.GetLogger(fmt.Sprintf("Listener:%d", int(id))),
		id:         id,
	}

	listener.l, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	listener.Go(listener.worker)
	return listener, nil
}
