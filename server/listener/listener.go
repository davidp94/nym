package listener

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/utils"

	"github.com/jstuczyn/CoconutGo/logger"
	"github.com/jstuczyn/CoconutGo/server/commands"

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
	// conn.SetDeadline(time.Now().Add(100 * time.Millisecond))

	var err error
	tmp := make([]byte, 4)
	if _, err = io.ReadFull(conn, tmp); err != nil {
		panic(err)
	}
	cmdLen := binary.BigEndian.Uint32(tmp)
	cmdBytes := make([]byte, cmdLen)
	if _, err = io.ReadFull(conn, cmdBytes); err != nil {
		panic(err)
	}

	cmd := commands.FromBytes(cmdBytes)
	resCh := make(chan interface{}, 1)
	cmdReq := commands.NewCommandRequest(cmd, resCh)
	l.incomingCh <- cmdReq
	l.resolveCommand(resCh, conn)
}

func (l *Listener) resolveCommand(resCh chan interface{}, conn net.Conn) {
	// time.Sleep(time.Second * 1)
	resInt := <-resCh
	switch res := resInt.(type) {

	case *coconut.Signature:
		l.log.Debug("Received signature")
		l.log.Debug(utils.ToCoconutString(res.Sig1()))
		l.log.Debug(utils.ToCoconutString(res.Sig2()))
		b, err := res.MarshalBinary()
		if err == nil {
			l.log.Notice("Writing Signature response to the client")
			conn.Write(b)
		}
	case *coconut.VerificationKey:
		l.log.Debug("Received VK")
		b, err := res.MarshalBinary()
		// todo: deal with so much repeating code regarding packet
		packet := make([]byte, 4+len(b))
		binary.BigEndian.PutUint32(packet, uint32(len(b)))
		copy(packet[4:], b)

		if err == nil {
			l.log.Notice("Writing VK response to the client")
			conn.Write(packet)
		}
	default:
		l.log.Error("Failed to resolve command")
		// currently client will panic because that string is shorter than anything that is expected
		// and is actually what we want
		conn.Write([]byte("Failed to resolve request"))

	}

}

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
