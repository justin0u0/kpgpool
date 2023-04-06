package pool

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/justin0u0/kpgpool/bpf"
	"github.com/justin0u0/kpgpool/pool/conn"
)

type Mode string

const (
	ModeTx      Mode = "transaction"
	ModeSession Mode = "session"
)

const maxClients = 1024

type Pool struct {
	remoteAddr string
	localAddr  string
	serverCh   chan *conn.Server
	servers    map[int]*conn.Server // maps proxy local port to server
	wg         sync.WaitGroup
	size       int
	mode       Mode
	mapDAO     *bpf.MapDAO
	bpf        bool
	ln         net.Listener
	cid        atomic.Uint32
}

func NewPool(remoteAddr, localAddr string, size int, mode Mode, mapDAO *bpf.MapDAO, bpf bool) *Pool {
	return &Pool{
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		servers:    make(map[int]*conn.Server, size),
		serverCh:   make(chan *conn.Server, size),
		size:       size,
		mode:       mode,
		mapDAO:     mapDAO,
		bpf:        bpf,
	}
}

func (p *Pool) Serve(ctx context.Context) error {
	if p.ln != nil {
		return nil
	}

	for i := 0; i < p.size; i++ {
		rconn, err := net.Dial("tcp4", p.remoteAddr)
		if err != nil {
			return fmt.Errorf("dial remote server: %w", err)
		}

		s := conn.NewServer(rconn)
		p.servers[rconn.LocalAddr().(*net.TCPAddr).Port] = s

		if err := s.Setup(); err != nil {
			return fmt.Errorf("setup server connection: %w", err)
		}

		if p.bpf {
			if err := p.setupBPFServerConn(rconn); err != nil {
				return fmt.Errorf("setup server bpf conn: %w", err)
			}

		} else {
			p.serverCh <- s
			go s.LoopReceive()
		}

		log.Println("Connected from", rconn.LocalAddr(), "to", rconn.RemoteAddr())
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

		go func() {
			p.wg.Add(1)
			defer p.wg.Done()

			if err := p.handleConn(ctx, conn); err != nil {
				log.Println("Failed to handle connection:", err)
			}
		}()
	}
}

func (p *Pool) Close() error {
	log.Println("Closing pool")

	if p.ln == nil {
		return nil
	}

	if err := p.ln.Close(); err != nil {
		return fmt.Errorf("close listener: %w", err)
	}

	log.Println("Closing server connections")
	for _, s := range p.servers {
		if err := s.Close(); err != nil {
			return fmt.Errorf("close server connection: %w", err)
		}
	}
	log.Println("All server connections are closed")

	log.Println("Closing client connections")
	p.wg.Wait()
	log.Println("All client connections are closed")

	return nil
}

func (p *Pool) handleConn(ctx context.Context, lconn net.Conn) error {
	cid := p.cid.Add(1)

	client := conn.NewClient(lconn, cid)
	defer client.Close()

	if err := client.Startup(); err != nil {
		return fmt.Errorf("start up client connection: %w", err)
	}

	if p.bpf {
		if err := p.setupBPFClientConn(lconn, cid); err != nil {
			return fmt.Errorf("setup client bpf conn: %w", err)
		}

		time.Sleep(100 * time.Millisecond)
		go p.startBPFProxy(client)
		time.Sleep(100 * time.Millisecond)
		go client.LoopReceive()
		time.Sleep(100 * time.Millisecond)

		if err := client.NotifyReady(); err != nil {
			return fmt.Errorf("notify ready: %w", err)
		}

		<-ctx.Done()
	} else {
		go client.LoopReceive()
		if err := client.NotifyReady(); err != nil {
			return fmt.Errorf("notify ready: %w", err)
		}

		if err := p.loopProxy(client); err != nil {
			return fmt.Errorf("setup proxy: %w", err)
		}
	}

	return nil
}

func (p *Pool) setupBPFServerConn(conn net.Conn) error {
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		return fmt.Errorf("get fd: %w", err)
	}
	defer f.Close()

	fd := uint32(f.Fd())

	if err := p.mapDAO.SetupServerState(conn); err != nil {
		return fmt.Errorf("setup server state: %w", err)
	}
	if err := p.mapDAO.RegisterServer(conn); err != nil {
		return fmt.Errorf("register server: %w", err)
	}
	if err := p.mapDAO.SetSockhash(conn, fd); err != nil {
		return fmt.Errorf("set sockhash: %w", err)
	}

	log.Println("Setup BPF server conn",
		conn.LocalAddr().String(), conn.RemoteAddr().String(), fd)
	return nil
}

func (p *Pool) setupBPFClientConn(conn net.Conn, id uint32) error {
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		return fmt.Errorf("get fd: %w", err)
	}
	defer f.Close()

	fd := uint32(f.Fd())

	if err := p.mapDAO.SetupClientState(conn, id); err != nil {
		return fmt.Errorf("setup client state: %w", err)
	}
	if err := p.mapDAO.SetSockhash(conn, fd); err != nil {
		return fmt.Errorf("set sockhash: %w", err)
	}

	log.Println("Setup BPF client conn",
		conn.LocalAddr().String(), conn.RemoteAddr().String(), fd)
	return nil
}

func (p *Pool) loopProxy(client *conn.Client) error {
	for {
		server := <-p.serverCh

		proxy := conn.NewProxy(server, client, p.mode == ModeTx)
		if err := proxy.Start(); err != nil {
			// When client terminates expectedly, we release the server and stop the
			// proxy loop.
			if errors.Is(err, conn.ErrClientTerminated) {
				p.serverCh <- server
				return nil
			}

			// When the server transaction completes, we release the server and
			// otherwise, we stop the proxy loop.
			if !errors.Is(err, conn.ErrServerTxComplete) {
				return err
			}
		}

		p.serverCh <- server
	}
}

func (p *Pool) startBPFProxy(client *conn.Client) {
	proxy := conn.NewBPFProxy(client, p.servers, p.mapDAO, p.mode == ModeTx)
	if err := proxy.Start(); err != nil {
		log.Println("Failed to run BPF proxy:", err)
	}
}
