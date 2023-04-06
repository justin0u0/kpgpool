package main

import (
	"log"

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
		Run:   runSelect1,
	}
	select1Cmd.Flags().StringP("url", "u", "postgres://postgres:postgres@localhost:6432/postgres?sslmode=disable", "pgbouncer url")
	select1Cmd.Flags().BoolP("keep-alive", "k", false, "keep connection alive")

	cmd.AddCommand(getLinksCmd, select1Cmd)

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

func runSelect1(cmd *cobra.Command, args []string) {
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
