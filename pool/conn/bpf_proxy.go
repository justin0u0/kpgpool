package conn

import (
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/justin0u0/kpgpool/bpf"
)

type BPFProxy struct {
	c       *Client
	servers map[int]*Server
	mapDAO  *bpf.MapDAO
	txMode  bool
}

func NewBPFProxy(
	c *Client,
	servers map[int]*Server,
	mapDAO *bpf.MapDAO,
	txMode bool,
) *BPFProxy {
	return &BPFProxy{
		c:       c,
		servers: servers,
		mapDAO:  mapDAO,
		txMode:  txMode,
	}
}

func (p *BPFProxy) Start() error {
	log.Printf("Start BPF proxy for client %s->%s",
		p.c.conn.RemoteAddr(), p.c.conn.LocalAddr())
	for {
		select {
		case msg, ok := <-p.c.ch:
			if !ok {
				return ErrClientClosed
			}

			// log.Printf("Received message from client: %T(%+v)", msg, msg)

			// don't send Terminate to the server
			if _, ok := msg.(*pgproto3.Terminate); ok {
				return ErrClientTerminated
			}

			cs, err := p.mapDAO.GetClientState(p.c.conn)
			if err != nil {
				return fmt.Errorf("get client binding: %w", err)
			}
			if cs.Valid == 0 {
				return fmt.Errorf("no server binding for client %s->%s",
					p.c.conn.RemoteAddr(), p.c.conn.LocalAddr())
			}

			s, ok := p.servers[int(cs.Server.LocalPort)]
			if !ok {
				return fmt.Errorf("server not found for port %d", cs.Server.LocalPort)
			}

			if p.txMode {
				switch m := msg.(type) {
				// We handle Parse messages to transform the name of the prepared
				// statement.
				case *pgproto3.Parse:
					// We'll mark the statement as prepared in the current session even
					// though we don't know if the Parse message will succeed.
					//
					// We can store `stmt` in the server state and mark it as prepared
					// after we receive ParseComplete message from the server for sake
					// of correctly handling the error case.
					//
					// However, we'll just keep it simple here and assume that the Parse
					// message will always succeed for now.
					s.prepared[m.Name] = struct{}{}
					p.c.prepared[m.Name] = m.Query

					p.mapDAO.UpdateServerStatePrepared(s.conn, []byte(m.Name))

				// We handle Bind messages to transform the name of the prepared
				// statement, as well as to inject Parse messages before Bind if it
				// hasn't been prepared in the current session.
				case *pgproto3.Bind:
					if _, ok := s.prepared[m.PreparedStatement]; !ok {
						msg := &pgproto3.Parse{
							Name:  m.PreparedStatement,
							Query: p.c.prepared[m.PreparedStatement],
						}
						// log.Printf("Send message to server: %T(%+v)", msg, msg)
						s.frontend.Send(msg)
						s.prepared[m.PreparedStatement] = struct{}{}

						p.mapDAO.UpdateServerStatePrepared(s.conn, []byte(m.PreparedStatement))
					}
				}
			}

			isPendingExtendedQueryMessages := false
			switch msg.(type) {
			case *pgproto3.Parse, *pgproto3.Describe, *pgproto3.Bind, *pgproto3.Execute:
				isPendingExtendedQueryMessages = true
			}

			s.frontend.Send(msg)
			if !isPendingExtendedQueryMessages {
				if err := s.frontend.Flush(); err != nil {
					return fmt.Errorf("send message to server: %w", err)
				}
			}
		}
	}
}
