package proxy

import (
	"fmt"
	"log"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

type Proxy struct {
	remoteAddr string
	localAddr  string
	ln         net.Listener
}

func NewProxy(remoteAddr, localAddr string) *Proxy {
	return &Proxy{
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}
}

func (p *Proxy) Serve() error {
	if p.ln == nil {
		return nil
	}

	ln, err := net.Listen("tcp", p.localAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.ln = ln

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		log.Printf("Handling connection from %s", conn.RemoteAddr())

		go p.handleConn(conn)
	}
}

func (p *Proxy) Close() error {
	if p.ln == nil {
		return nil
	}

	return p.ln.Close()
}

func (p *Proxy) handleConn(lconn net.Conn) {
	defer lconn.Close()

	backend := pgproto3.NewBackend(lconn, lconn)
	if err := p.handleStartupMessage(backend); err != nil {
		log.Println("Failed to handle startup message:", err)
		return
	}

	rconn, err := net.Dial("tcp4", p.remoteAddr)
	if err != nil {
		log.Println("Failed to connect to remote server:", err)
		return
	}
	defer rconn.Close()
}

func (p *Proxy) handleStartupMessage(backend *pgproto3.Backend) error {
	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return fmt.Errorf("receive startup message: %w", err)
	}

	switch msg := msg.(type) {
	case *pgproto3.StartupMessage:
		return nil
	case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest, *pgproto3.CancelRequest:
		return fmt.Errorf("unsupported startup message: %T", msg)
	default:
		return fmt.Errorf("unexpected startup message: %T", msg)
	}
}
