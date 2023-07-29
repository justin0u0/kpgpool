package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use: "bpfpgpool [command]",
	}

	cmd.AddCommand(
		loadBpfCommand(),
		pgCommand(),
		pgbouncerCommand(),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := cmd.ExecuteContext(ctx); err != nil {
		panic(err)
	}
}
