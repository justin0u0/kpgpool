package client

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/jackc/pgx/v5/pgproto3"
)

type pgStepClient struct {
	remoteAddr string
}

func NewPgStepClient(remoteAddr string) *pgStepClient {
	return &pgStepClient{
		remoteAddr: remoteAddr,
	}
}

func (c *pgStepClient) Start(ctx context.Context) {
	conn, err := net.Dial("tcp4", c.remoteAddr)
	if err != nil {
		log.Fatal("Failed to connect to remote server:", err)
	}
	defer conn.Close()

	startupMsg := &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":             "postgres",
			"database":         "postgres",
			"client_encoding":  "UTF8",
			"application_name": "bpfpgpool",
		},
	}

	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(startupMsg)
	if err := frontend.Flush(); err != nil {
		log.Fatal("Failed to send startup message:", err)
	}
	log.Println("Sent startup message done")

	c.Wait(ctx)

	frontend.Send(&pgproto3.Query{
		String: "SELECT 1;",
	})
	if err := frontend.Flush(); err != nil {
		log.Fatal("Failed to send query:", err)
	}
	log.Println("Sent query done")

	c.Wait(ctx)

	frontend.Send(&pgproto3.Terminate{})
	if err := frontend.Flush(); err != nil {
		log.Fatal("Failed to send terminate:", err)
	}
	log.Println("Sent terminate done")
}

// Wait waits for STDIN or ctx.Done()
func (c *pgStepClient) Wait(ctx context.Context) {
	fmt.Print("Enter Y to continue: ")

	done := make(chan struct{})

	go func() {
		defer close(done)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if scanner.Text() == "Y" {
				return
			}
			fmt.Print("Enter Y to continue: ")
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
