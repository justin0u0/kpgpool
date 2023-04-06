package conn

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

var startupMessage = &pgproto3.StartupMessage{
	ProtocolVersion: pgproto3.ProtocolVersionNumber,
	Parameters: map[string]string{
		"user":     "postgres",
		"database": "postgres",
	},
}

type Server struct {
	conn     net.Conn
	frontend *pgproto3.Frontend
	ch       chan pgproto3.BackendMessage
	done     chan struct{}
	prepared map[string]struct{}
}

func NewServer(conn net.Conn) *Server {
	return &Server{
		conn:     conn,
		frontend: pgproto3.NewFrontend(conn, conn),
		ch:       make(chan pgproto3.BackendMessage),
		done:     make(chan struct{}),
		prepared: make(map[string]struct{}),
	}
}

func (s *Server) Setup() error {
	s.frontend.Send(startupMessage)
	if err := s.frontend.Flush(); err != nil {
		return fmt.Errorf("send startup message: %w", err)
	}

	// We assume that no further messages need to be sent to the server, just
	// receive messages from the server until ReadyForQuery.
	//
	// Remember to set authentication mode to trust in the PostgreSQL config.
	for {
		msg, err := s.frontend.Receive()
		if err != nil {
			return fmt.Errorf("receive message: %w", err)
		}

		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	log.Println("Complete server setup",
		s.conn.LocalAddr(), "->", s.conn.RemoteAddr())
	return nil
}

func (s *Server) LoopReceive() {
	defer close(s.ch)
	defer close(s.done)

	log.Println("Start receiving message from the server:",
		s.conn.LocalAddr(), "->", s.conn.RemoteAddr())
	for {
		msg, err := s.frontend.Receive()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Println("Failed to receive message from the server:", err)
			}
			return
		}
		s.ch <- msg
	}
}

func (s *Server) Close() error {
	log.Println("Closing server connection:",
		s.conn.LocalAddr(), "->", s.conn.RemoteAddr())
	if err := s.conn.Close(); err != nil {
		return fmt.Errorf("close connection: %w", err)
	}
	<-s.done
	return nil
}
