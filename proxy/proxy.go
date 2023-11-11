package proxy

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/justin0u0/bpfpgpool/bpf"
)

type Proxy struct {
	remoteAddr string
	localAddr  string
	mapDAO     *bpf.MapDAO
	ln         net.Listener
}

func NewProxy(remoteAddr, localAddr string, mapDAO *bpf.MapDAO) *Proxy {
	return &Proxy{
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		mapDAO:     mapDAO,
	}
}

func (p *Proxy) Serve() error {
	if p.ln != nil {
		return nil
	}

	ln, err := net.Listen("tcp4", p.localAddr)
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

	rconn, err := net.DialTimeout("tcp4", p.remoteAddr, 1*time.Second)
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
	log.Println("Sent startup message:", msg)

	// Starting to forward traffic
	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		log.Println("Starting to forward traffic from client to server")
		defer wg.Done()

		for {
			log.Println("Waiting to receive message from client")

			msg, err := backend.Receive()
			if err != nil {
				log.Println("Failed to receive message from client:", err)
				return
			}
			log.Printf("Received message from client: %T(%+v)", msg, msg)

			frontend.Send(msg)
			if err := frontend.Flush(); err != nil {
				log.Println("Failed to send message to server:", err)
				return
			}
			log.Printf("Sent message to server: %T(%+v)", msg, msg)
		}
	}()

	go func() {
		log.Println("Starting to forward traffic from server to client")
		defer wg.Done()

		for {
			log.Println("Waiting to receive message from server")

			msg, err := frontend.Receive()
			if err != nil {
				log.Println("Failed to receive message from server:", err)
				return
			}
			log.Printf("Received message from server: %T(%+v)", msg, msg)

			backend.Send(msg)
			if err := backend.Flush(); err != nil {
				log.Println("Failed to send message to client:", err)
				return
			}
			log.Printf("Sent message to client: %T(%+v)", msg, msg)
		}
	}()

	go func() {
		time.Sleep(5 * time.Second)
		p.SetupBPFProxy(lconn, rconn)
	}()

	log.Println("Waiting for goroutines to finish")
	wg.Wait()
	log.Println("Goroutines finished")
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

func (p *Proxy) SetupBPFProxy(lconn, rconn net.Conn) {
	lf, err := lconn.(*net.TCPConn).File()
	if err != nil {
		log.Println("Failed to get file descriptor of local connection:", err)
		return
	}
	defer lf.Close()
	lfd := uint32(lf.Fd())
	clientPort := uint32(lconn.RemoteAddr().(*net.TCPAddr).Port)

	rf, err := rconn.(*net.TCPConn).File()
	if err != nil {
		log.Println("Failed to get file descriptor of remote connection:", err)
		return
	}
	defer rf.Close()
	rfd := uint32(rf.Fd())
	poolerPort := uint32(rconn.LocalAddr().(*net.TCPAddr).Port)

	log.Println("Setting up BPF maps",
		"[ clientPort ->", clientPort, "]",
		"[ poolerPort ->", poolerPort, "]",
		"[ lfd ->", lfd, "]",
		"[ rfd ->", rfd, "]",
	)

	if err := p.mapDAO.SetP2C(poolerPort, clientPort); err != nil {
		log.Println("Failed to set p2c map:", err)
		return
	}
	log.Printf("Set p2c map: %d -> %d", poolerPort, clientPort)
	if err := p.mapDAO.SetC2P(clientPort, poolerPort); err != nil {
		log.Println("Failed to set c2p map:", err)
		return
	}
	log.Printf("Set c2p map: %d -> %d", clientPort, poolerPort)

	if err := p.mapDAO.SetP2SSockmap(poolerPort, rfd); err != nil {
		log.Println("Failed to set p2s sockmap:", err)
		return
	}
	log.Printf("Set p2s sockmap: %d -> %d", poolerPort, rfd)
	if err := p.mapDAO.SetC2PSockmap(clientPort, lfd); err != nil {
		log.Println("Failed to set c2p sockmap:", err)
		return
	}
	log.Printf("Set c2p sockmap: %d -> %d", clientPort, lfd)
}
