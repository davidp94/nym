package listener

import (
	"fmt"
	"io/ioutil"
	"net"
	"sync"

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
	l.log.Debug("onNewConn called")
	// conn.SetDeadline(time.Now().Add(100 * time.Millisecond))

	// read only a single byte
	// b0 := make([]byte, 1)
	// if _, err := io.ReadFull(conn, b0); err != nil {
	// 	panic(err)
	// }
	res, err := ioutil.ReadAll(conn)
	if err != nil {
		panic(err)
	}
	cmd := commands.FromBytes(res)
	l.incomingCh <- cmd
	// how to get result here and write back to client?

	b := []byte("Hello World")
	conn.Write(b)
	conn.Close()
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
