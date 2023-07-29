package main

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
)

func pgCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "pg [command]",
	}

	loopQueryCmd := &cobra.Command{
		Use:   "loop-query",
		Short: "run `select * from test_table limit 1` in periodic",
		Run:   runPgLoopQuery,
	}
	loopQueryCmd.Flags().StringP("url", "u", "postgres://postgres:password@10.121.240.164:6432/postgres?sslmode=disable&connect_timeout=5", "")
	// loopQueryCmd.Flags().StringP("url", "u", "postgres://postgres:password@10.121.240.164:6432/postgres?sslmode=disable", "")
	loopQueryCmd.Flags().DurationP("interval", "i", 5*time.Second, "query interval")
	loopQueryCmd.Flags().IntP("concurrency", "c", 1, "connection concurrency")

	cmd.AddCommand(loopQueryCmd)

	return cmd
}

func runPgLoopQuery(cmd *cobra.Command, args []string) {
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
			pgSingleLoopQuery(ctx, url, interval)
		}()
	}

	wg.Wait()
}

func pgSingleLoopQuery(ctx context.Context, url string, interval time.Duration) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		log.Fatalf("failed to open connection %s: %v", url, err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("failed to ping: %v", err)
	}
	log.Printf("ping success %s", url)

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			log.Printf("executing query")
			if _, err := db.ExecContext(ctx, "select * from test_table limit 1"); err != nil {
				log.Fatalf("failed to execute query: %v", err)
			}
		}
	}
}
