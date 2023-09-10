package main

import (
	"github.com/justin0u0/bpfpgpool/client"
	"github.com/spf13/cobra"
)

func clientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "client",
		Run: runClient,
	}

	return cmd
}

func runClient(cmd *cobra.Command, args []string) {
	c := client.NewPgStepClient(
		"10.121.240.150:6432",
	)
	c.Start(cmd.Context())
}
