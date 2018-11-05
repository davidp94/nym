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

	// read only a single byte
	// b0 := make([]byte, 1)
	// if _, err := io.ReadFull(conn, b0); err != nil {
	// 	panic(err)
	// }
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
	// time.Sleep(time.Second * 1)
	sigRes := <-resCh
	switch sig := sigRes.(type) {
	case error:
		l.log.Error("Failed to sign message")
		// currently client will panic because that string is shorter than 2EC
		// and is actually what we want
		conn.Write([]byte("Failed to sign message"))
	case *coconut.Signature:
		l.log.Debug("Received signature")
		l.log.Debug(utils.ToCoconutString(sig.Sig1()))
		l.log.Debug(utils.ToCoconutString(sig.Sig2()))
		b, err := sig.MarshalBinary()
		if err == nil {
			l.log.Notice("Writing Signature response to the client")
			conn.Write(b)
		}
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
