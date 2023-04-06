package main

import (
	"log"
	"time"

	"github.com/justin0u0/kpgpool/client"
	"github.com/spf13/cobra"
)

func clientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "client",
	}

	basicCmd := &cobra.Command{
		Use: "basic",
		Run: runBasicClient,
	}
	basicCmd.Flags().StringP("url", "u", "postgres://postgres:postgres@10.121.240.150:6432/postgres?sslmode=disable&default_query_exec_mode=simple_protocol", "url")
	basicCmd.Flags().IntP("concurrency", "c", 3, "concurrency")

	extendedCmd := &cobra.Command{
		Use: "extended",
		Run: runExtendedClient,
	}
	extendedCmd.Flags().StringP("url", "u", "10.121.240.150:6432", "url")

	benchCmd := &cobra.Command{
		Use: "bench",
		Run: runBenchClient,
	}
	benchCmd.Flags().StringP("url", "u", "postgres://postgres:postgres@10.121.240.150:6432/postgres?sslmode=disable&default_query_exec_mode=simple_protocol", "url")
	benchCmd.Flags().IntP("concurrency", "c", 10, "concurrency")
	benchCmd.Flags().IntP("rows", "r", 1000, "rows")
	benchCmd.Flags().DurationP("duration", "d", 30*time.Second, "duration")
	benchCmd.Flags().DurationP("warmup", "w", 1*time.Second, "warmup")
	benchCmd.Flags().IntP("query-per-tx", "q", 0, "query per transaction")
	benchCmd.Flags().BoolP("bootstrap", "b", false, "bootstrap")

	cmd.AddCommand(basicCmd, extendedCmd, benchCmd)

	return cmd
}

func runBasicClient(cmd *cobra.Command, args []string) {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Fatalln("Failed to get url flag:", err)
	}
	concurrency, err := cmd.Flags().GetInt("concurrency")
	if err != nil {
		log.Fatalln("Failed to get concurrency flag:", err)
	}

	c := client.NewBasicClient(url, concurrency)
	c.Run(cmd.Context())

	log.Println("Done")
}

func runBenchClient(cmd *cobra.Command, args []string) {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Fatalln("Failed to get url flag:", err)
	}

	concurrency, err := cmd.Flags().GetInt("concurrency")
	if err != nil {
		log.Fatalln("Failed to get concurrency flag:", err)
	}
	rows, err := cmd.Flags().GetInt("rows")
	if err != nil {
		log.Fatalln("Failed to get rows flag:", err)
	}
	duration, err := cmd.Flags().GetDuration("duration")
	if err != nil {
		log.Fatalln("Failed to get duration flag:", err)
	}
	warmup, err := cmd.Flags().GetDuration("warmup")
	if err != nil {
		log.Fatalln("Failed to get warmup flag:", err)
	}
	queryPerTx, err := cmd.Flags().GetInt("query-per-tx")
	if err != nil {
		log.Fatalln("Failed to get query-per-tx flag:", err)
	}
	bootstrap, err := cmd.Flags().GetBool("bootstrap")
	if err != nil {
		log.Fatalln("Failed to get bootstrap flag:", err)
	}

	c, err := client.NewPgBenchClient(
		cmd.Context(),
		url, concurrency, rows, duration, warmup, queryPerTx, bootstrap,
	)
	if err != nil {
		log.Fatalln("Failed to create client:", err)
	}
	c.Run(cmd.Context())
}

func runExtendedClient(cmd *cobra.Command, args []string) {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Fatalln("Failed to get url flag:", err)
	}

	c := client.NewExtendedClient(url)
	c.Run(cmd.Context())

	log.Println("Done")
}
