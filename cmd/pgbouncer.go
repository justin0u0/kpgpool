package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/justin0u0/bpfpgpool/pooler"
	"github.com/spf13/cobra"
)

func pgbouncerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "pgbouncer [command]",
		Args: cobra.ExactArgs(1),
	}

	getLinksCmd := &cobra.Command{
		Use:   "get-links",
		Short: "get client-server links",
		Run:   runPgbouncerGetLinks,
	}
	getLinksCmd.Flags().StringP("url", "u", "postgres://postgres:postgres@localhost:6432/pgbouncer?sslmode=disable&default_query_exec_mode=simple_protocol", "pgbouncer url")

	select1Cmd := &cobra.Command{
		Use:   "select-1",
		Short: "run `select 1`",
		Run:   runPgbouncerSelect1,
	}
	select1Cmd.Flags().StringP("url", "u", "postgres://postgres:postgres@localhost:6432/postgres?sslmode=disable", "pgbouncer url")
	select1Cmd.Flags().BoolP("keep-alive", "k", false, "keep connection alive")

	loopQueryCmd := &cobra.Command{
		Use:   "loop-query",
		Short: "run `select * from test_table` in periodic",
		Run:   runPgbouncerLoopQuery,
	}
	loopQueryCmd.Flags().StringP("url", "u", "user=postgres password=postgres host=127.0.0.1 port=6432 dbname=postgres sslmode=disable", "pgbouncer url")
	loopQueryCmd.Flags().DurationP("interval", "i", 5*time.Second, "query interval")
	loopQueryCmd.Flags().IntP("concurrency", "c", 1, "connection concurrency")

	cmd.AddCommand(getLinksCmd, select1Cmd, loopQueryCmd)

	return cmd
}

func runPgbouncerGetLinks(cmd *cobra.Command, args []string) {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Fatalf("failed to get url flag: %v", err)
	}

	ctx := cmd.Context()

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		log.Fatalf("failed to connect to PostgreSQL: %v", err)
	}
	defer conn.Close(ctx)

	p := pooler.NewPgbouncerPooler(conn)
	links, err := p.GetLinks(ctx)
	if err != nil {
		log.Fatalf("failed to get links: %v", err)
	}

	for _, link := range links {
		log.Println("clientIP:", link.ClientIP, "clientPort:", link.ClientPort, "serverPort:", link.ServerPort)
	}
}

func runPgbouncerSelect1(cmd *cobra.Command, args []string) {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Fatalf("failed to get url flag: %v", err)
	}

	keepAlive, err := cmd.Flags().GetBool("keep-alive")
	if err != nil {
		log.Fatalf("failed to get keep-alive flag: %v", err)
	}

	ctx := cmd.Context()

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		log.Fatalf("failed to connect to PostgreSQL: %v", err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
		log.Fatalf("failed to execute a query: %v", err)
	}

	log.Println("executed a query")

	if keepAlive {
		<-ctx.Done()
	}
}

func runPgbouncerLoopQuery(cmd *cobra.Command, args []string) {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Fatalf("failed to get url flag: %v", err)
	}

	interval, err := cmd.Flags().GetDuration("interval")
	if err != nil {
		log.Fatalf("failed to get interval flag: %v", err)
	}

	concurrency, err := cmd.Flags().GetInt("concurrency")
	if err != nil {
		log.Fatalf("failed to get concurrency flag: %v", err)
	}

	ctx := cmd.Context()

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pgbouncerSingleLoopQuery(ctx, url, interval)
		}()
	}

	wg.Wait()
}

func pgbouncerSingleLoopQuery(ctx context.Context, url string, interval time.Duration) {
	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx2, url)
	if err != nil {
		log.Fatalf("failed to connect to PostgreSQL %s: %v", url, err)
	}
	defer conn.Close(ctx)

	pgconn := conn.PgConn()
	log.Println("connect pooler:", pgconn.Conn().LocalAddr(), "->", pgconn.Conn().RemoteAddr())

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}

		log.Println("executing query")
		if _, err := conn.Exec(ctx, "SELECT * FROM test_table"); err != nil {
			log.Fatalf("failed to execute a query: %v", err)
		}
	}
}
