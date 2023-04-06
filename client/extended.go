package client

import (
	"context"
	"log"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

type extendedClient struct {
	url string
}

func NewExtendedClient(url string) *extendedClient {
	return &extendedClient{
		url: url,
	}
}

var startupMessage = &pgproto3.StartupMessage{
	ProtocolVersion: pgproto3.ProtocolVersionNumber,
	Parameters: map[string]string{
		"user":     "postgres",
		"database": "postgres",
	},
}

func (c *extendedClient) Run(ctx context.Context) {
	conn, err := net.Dial("tcp", c.url)
	if err != nil {
		log.Fatalf("Failed to dial %s: %v", c.url, err)
	}
	defer conn.Close()

	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(startupMessage)
	if err := frontend.Flush(); err != nil {
		log.Fatalf("Failed to send startup message: %v", err)
	}

	for {
		msg, err := frontend.Receive()
		if err != nil {
			log.Fatalf("Failed to receive message: %v", err)
		}

		log.Printf("Received message from server %T(%+v)", msg, msg)

		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	stmtName := "stmtcache_001"

	frontend.Send(&pgproto3.Parse{
		Name:          stmtName,
		Query:         "SELECT * FROM kpgpool_bench WHERE id = $1",
		ParameterOIDs: []uint32{},
	})
	frontend.Send(&pgproto3.Describe{
		ObjectType: 'S',
		Name:       stmtName,
	})
	frontend.Send(&pgproto3.Sync{})
	if err := frontend.Flush(); err != nil {
		log.Fatalf("Failed to send Parse: %v", err)
	}

	for {
		msg, err := frontend.Receive()
		if err != nil {
			log.Fatalf("Failed to receive message: %v", err)
		}

		log.Printf("Received message from server %T(%+v)", msg, msg)

		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	frontend.Send(&pgproto3.Bind{
		PreparedStatement:    stmtName,
		ParameterFormatCodes: []int16{0x01},
		Parameters:           [][]byte{{0x00, 0x00, 0x01, 0xdf}},
		ResultFormatCodes:    []int16{0x01},
	})
	frontend.Send(&pgproto3.Describe{
		ObjectType: 'S',
		Name:       stmtName,
	})
	frontend.Send(&pgproto3.Execute{})
	frontend.Send(&pgproto3.Sync{})
	if err := frontend.Flush(); err != nil {
		log.Fatalf("Failed to send Bind: %v", err)
	}

	for {
		msg, err := frontend.Receive()
		if err != nil {
			log.Fatalf("Failed to receive message: %v", err)
		}

		log.Printf("Received message from server %T(%+v)", msg, msg)

		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
}
