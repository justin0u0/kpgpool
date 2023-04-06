package conn

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

var startupMessageRespones = []pgproto3.BackendMessage{
	&pgproto3.AuthenticationOk{},
	&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"},
	&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"},
	&pgproto3.ParameterStatus{Name: "server_version", Value: "15.3 (Debian 15.3-1.pgdg120+1)"},
	&pgproto3.BackendKeyData{ProcessID: 1234, SecretKey: 5678},
	&pgproto3.ReadyForQuery{TxStatus: 'I'},
}

type Client struct {
	conn    net.Conn
	id      uint32
	backend *pgproto3.Backend
	ch      chan pgproto3.FrontendMessage
	// prepared maps the name of the prepared statement to the query string.
	prepared map[string]string
	done     chan struct{}
}

func NewClient(conn net.Conn, id uint32) *Client {
	return &Client{
		conn:     conn,
		id:       id,
		backend:  pgproto3.NewBackend(conn, conn),
		ch:       make(chan pgproto3.FrontendMessage),
		prepared: make(map[string]string),
		done:     make(chan struct{}),
	}
}

func (c *Client) Startup() error {
	msg, err := c.backend.ReceiveStartupMessage()
	if err != nil {
		return fmt.Errorf("receive startup message: %w", err)
	}
	log.Println("Received startup message:", msg)
	return nil
}

func (c *Client) NotifyReady() error {
	for _, msg := range startupMessageRespones {
		c.backend.Send(msg)
	}
	if err := c.backend.Flush(); err != nil {
		return fmt.Errorf("send startup messages: %w", err)
	}

	log.Println("Notified ready to the client:",
		c.conn.RemoteAddr(), "->", c.conn.LocalAddr())
	return nil
}

func (c *Client) LoopReceive() {
	defer close(c.ch)
	defer close(c.done)

	log.Println("Start receiving message from the client:",
		c.conn.RemoteAddr(), "->", c.conn.LocalAddr())
	for {
		msg, err := c.backend.Receive()
		if err != nil {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Println("Failed to receive message from the client:", err)
			}
			return
		}

		c.ch <- msg
	}
}

func (c *Client) Close() error {
	log.Println("Closing client connection:",
		c.conn.RemoteAddr(), "->", c.conn.LocalAddr())
	if err := c.conn.Close(); err != nil {
		return err
	}
	<-c.done
	return nil
}
