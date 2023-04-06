package conn

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
)

var (
	ErrClientTerminated = errors.New("client terminated expectedly")
	ErrClientClosed     = errors.New("client closed unexpectedly")
	ErrServerTxComplete = errors.New("server transaction complete")
	ErrServerClosed     = errors.New("server closed unexpectedly")
)

const maxIdentifierLength = 63

type Proxy struct {
	s      *Server
	c      *Client
	txMode bool
}

func NewProxy(s *Server, c *Client, txMode bool) *Proxy {
	return &Proxy{
		s:      s,
		c:      c,
		txMode: txMode,
	}
}

func (p *Proxy) Start() error {
	for {
		select {
		case msg, ok := <-p.c.ch:
			if !ok {
				return ErrClientClosed
			}

			// don't send Terminate to the server
			if _, ok := msg.(*pgproto3.Terminate); ok {
				return ErrClientTerminated
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
					p.s.prepared[m.Name] = struct{}{}
					p.c.prepared[m.Name] = m.Query

				// We handle Bind messages to transform the name of the prepared
				// statement, as well as to inject Parse messages before Bind if it
				// hasn't been prepared in the current session.
				case *pgproto3.Bind:
					if _, ok := p.s.prepared[m.PreparedStatement]; !ok {
						msg := &pgproto3.Parse{
							Name:  m.PreparedStatement,
							Query: p.c.prepared[m.PreparedStatement],
						}
						// log.Printf("Send message to server: %T(%+v)", msg, msg)
						p.s.frontend.Send(msg)
						p.s.prepared[m.PreparedStatement] = struct{}{}
					}
				}
			}

			isPendingExtendedQueryMessages := false
			switch msg.(type) {
			case *pgproto3.Parse, *pgproto3.Describe, *pgproto3.Bind, *pgproto3.Execute:
				isPendingExtendedQueryMessages = true
			}

			p.s.frontend.Send(msg)
			if !isPendingExtendedQueryMessages {
				if err := p.s.frontend.Flush(); err != nil {
					return fmt.Errorf("send message to server: %w", err)
				}
			}
		case msg, ok := <-p.s.ch:
			if !ok {
				return ErrServerClosed
			}

			isReadyForQuery := false
			isReadyForQueryIdle := false
			if m, ok := msg.(*pgproto3.ReadyForQuery); ok {
				isReadyForQuery = true
				if m.TxStatus == 'I' {
					isReadyForQueryIdle = true
				}
			}

			// We buffer as much as possible, until ReadyForQuery
			// log.Printf("Send message to client: %T(%+v)", msg, msg)
			p.c.backend.Send(msg)

			if isReadyForQuery {
				// log.Println("Send message to client:", msg)
				if err := p.c.backend.Flush(); err != nil {
					return fmt.Errorf("send message to client: %w", err)
				}
			}

			if p.txMode && isReadyForQueryIdle {
				return ErrServerTxComplete
			}
		}
	}
}
