package main

import (
	"errors"
	"log"
	"os"
	"runtime/pprof"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/justin0u0/kpgpool/bpf"
	"github.com/justin0u0/kpgpool/pool"
	"github.com/spf13/cobra"
)

func poolCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "pool",
		Run: runPool,
	}
	cmd.Flags().BoolP("bpf", "b", false, "use bpf proxy")
	cmd.Flags().StringP("url", "u", "10.140.0.10:5432", "database URL")
	cmd.Flags().IntP("port", "p", 6432, "pool port")
	cmd.Flags().IntP("size", "s", 10, "pool size")
	cmd.Flags().StringP("mode", "m", "transaction", "pooling mode, transaction or session")
	cmd.Flags().Bool("pprof", false, "enable pprof CPU profiling")

	return cmd
}

func runPool(cmd *cobra.Command, args []string) {
	bpfEnabled, err := cmd.Flags().GetBool("bpf")
	if err != nil {
		log.Fatalln("Failed to get bpf flag:", err)
	}
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		log.Fatalln("Failed to get url flag:", err)
	}
	port, err := cmd.Flags().GetInt("port")
	if err != nil {
		log.Fatalln("Failed to get port flag:", err)
	}
	size, err := cmd.Flags().GetInt("size")
	if err != nil {
		log.Fatalln("Failed to get size flag:", err)
	}
	mode, err := cmd.Flags().GetString("mode")
	if err != nil {
		log.Fatalln("Failed to get mode flag:", err)
	}
	var poolMode pool.Mode
	switch mode {
	case "transaction":
		poolMode = pool.ModeTx
	case "session":
		poolMode = pool.ModeSession
	default:
		log.Fatalf("invalid mode: %s", mode)
	}
	pprofEnabled, err := cmd.Flags().GetBool("pprof")
	if err != nil {
		log.Fatalln("Failed to get pprof flag:", err)
	}

	objs, err := bpf.LoadObjects()
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			for _, l := range ve.Log {
				log.Println(l)
			}
		}
		log.Fatalf("failed to load bpf objects: %v", err)
	}
	defer objs.Close()
	log.Println("Loaded bpf objects")

	if bpfEnabled {
		detach, err := bpf.AttachProgram(objs, bpf.ProgramPool)
		if err != nil {
			log.Fatalf("failed to attach program: %v", err)
		}
		defer detach()
		log.Println("Attached bpf program")
	}

	ctx := cmd.Context()

	if pprofEnabled {
		f, err := os.Create("/pprof/cpu.prof")
		if err != nil {
			log.Fatalln("Failed to create cpu.prof:", err)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatalln("Failed to start CPU profiling:", err)
		}
		log.Println("Started CPU profiling")

		defer func() {
			log.Println("Stopping CPU profiling")
			pprof.StopCPUProfile()
			log.Println("Stopped CPU profiling")
		}()
	}

	p := pool.NewPool(
		url,
		":"+strconv.Itoa(port),
		size,
		poolMode,
		&bpf.MapDAO{Objs: objs},
		bpfEnabled,
	)
	if err := p.Serve(ctx); err != nil {
		log.Println("Failed to serve:", err)
	}

	<-ctx.Done()

	if err := p.Close(); err != nil {
		log.Println("Failed to close:", err)
	}

	log.Println("Done")
}
