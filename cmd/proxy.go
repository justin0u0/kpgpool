package main

import (
	"log"

	"github.com/justin0u0/bpfpgpool/bpf"
	"github.com/justin0u0/bpfpgpool/proxy"
	"github.com/spf13/cobra"
)

func proxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "proxy",
		Run: runProxy,
	}
	cmd.Flags().BoolP("bpf", "b", false, "enable bpf")

	return cmd
}

func runProxy(cmd *cobra.Command, args []string) {
	bpfEnabled, err := cmd.Flags().GetBool("bpf")
	if err != nil {
		log.Fatalf("failed to get bpf flag: %v", err)
	}
	log.Printf("bpf enabled: %v", bpfEnabled)

	if bpfEnabled {
		objs, err := bpf.LoadObjects()
		if err != nil {
			log.Fatalf("failed to load bpf objects: %v", err)
		}
		defer objs.Close()
		log.Println("Loaded bpf objects")

		{
			detach, err := bpf.AttachProgram(objs, bpf.ProgramSockops)
			if err != nil {
				log.Fatalf("failed to attach program: %v", err)
			}
			defer detach()
			log.Println("Attached sockops program")
		}

		{
			detach, err := bpf.AttachProgram(objs, bpf.ProgramSkSkb)
			if err != nil {
				log.Fatalf("failed to attach program: %v", err)
			}
			defer detach()
			log.Println("Attached sk_skb program")
		}
	}

	p := proxy.NewProxy(
		"10.121.240.151:5432",
		"10.121.240.150:6432",
	)
	if err := p.Serve(); err != nil {
		panic(err)
	}
}
