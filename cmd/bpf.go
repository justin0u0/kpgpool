package main

import (
	"log"
	"strconv"

	"github.com/justin0u0/bpfpgpool/bpfgo"
	"github.com/spf13/cobra"
)

func loadBpfCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "bpf [command]",
		Args: cobra.ExactArgs(1),
	}

	loadSkLookupCommand := &cobra.Command{
		Use:   "load-sk-lookup [program]",
		Short: "load the sk_lookup program",
		Run:   runLoadSklookupProg,
		Args:  cobra.ExactArgs(1),
	}

	// FIXME:
	// map is not updated although the program does not return any error
	updateSockhashCommand := &cobra.Command{
		Use:   "update-sockhash [pid] [fd] [key]",
		Short: "update the sockhash map",
		Run:   runUpdateSockhashMap,
		Args:  cobra.ExactArgs(3),
	}

	cmd.AddCommand(
		loadSkLookupCommand,
		updateSockhashCommand,
	)

	return cmd
}

func runLoadSklookupProg(cmd *cobra.Command, args []string) {
	bpfgo.LoadSklookupProg(cmd.Context(), args[0])
}

func runUpdateSockhashMap(cmd *cobra.Command, args []string) {
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		log.Fatalf("could not parse pid: %s", err)
	}
	fd, err := strconv.Atoi(args[1])
	if err != nil {
		log.Fatalf("could not parse fd: %s", err)
	}
	key, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		log.Fatalf("could not parse key: %s", err)
	}

	bpfgo.UpdateSockhashMap(pid, fd, key)
}
