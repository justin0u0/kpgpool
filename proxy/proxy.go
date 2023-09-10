package proxy

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"

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
	if p.ln != nil {
		return nil
	}

	ln, err := net.Listen("tcp", p.localAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.ln = ln
	log.Println("Listening on", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}

		log.Println("Handling connection from", conn.RemoteAddr())

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

	msg, err := p.handleStartupMessage(backend)
	if err != nil {
		log.Println("Failed to handle startup message:", err)
		return
	}
	log.Println("Received startup message:", msg)

	rconn, err := net.Dial("tcp4", p.remoteAddr)
	if err != nil {
		log.Println("Failed to connect to remote server:", err)
		return
	}
	defer rconn.Close()
	log.Println("Connected to remote server", rconn.RemoteAddr())

	frontend := pgproto3.NewFrontend(rconn, rconn)
	frontend.Send(msg)
	if err := frontend.Flush(); err != nil {
		log.Println("Failed to send startup message:", err)
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		buf := make([]byte, 32768)
		for {
			n, err := lconn.Read(buf)
			if err != nil {
				log.Println("Failed to read from client:", err)
				return
			}

			log.Printf("Received %d bytes from client\n%s\n\n", n, hex.Dump(buf[:n]))

			if _, err := rconn.Write(buf[:n]); err != nil {
				log.Println("Failed to write to server:", err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()

		buf := make([]byte, 32768)
		for {
			n, err := rconn.Read(buf)
			if err != nil {
				log.Println("Failed to read from server:", err)
				return
			}

			log.Printf("Received %d bytes from server\n%s\n\n", n, hex.Dump(buf[:n]))

			if _, err := lconn.Write(buf[:n]); err != nil {
				log.Println("Failed to write to client:", err)
				return
			}
		}
	}()

	wg.Wait()
}

func (p *Proxy) handleStartupMessage(backend *pgproto3.Backend) (pgproto3.FrontendMessage, error) {
	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return nil, fmt.Errorf("receive startup message: %w", err)
	}

	switch msg := msg.(type) {
	case *pgproto3.StartupMessage:
		return msg, nil
	case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest, *pgproto3.CancelRequest:
		return nil, fmt.Errorf("unsupported startup message: %T", msg)
	default:
		return nil, fmt.Errorf("unexpected startup message: %T", msg)
	}
}
