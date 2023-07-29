package main

import (
	"log"

	"github.com/justin0u0/bpfpgpool/bpf"
	"github.com/spf13/cobra"
)

func loadBpfCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "bpf [command]",
		Args: cobra.ExactArgs(1),
	}

	loadCmd := &cobra.Command{
		Use:   "load",
		Short: "load bpf programs",
		Run:   runLoad,
	}

	cmd.AddCommand(loadCmd)

	return cmd
}

var bpffs = "/usr/fs/bpf"

func runLoad(cmd *cobra.Command, args []string) {
	objs, err := bpf.LoadObjects()
	if err != nil {
		log.Fatalf("failed to load bpf objects: %v", err)
	}
	defer objs.Close()

	{
		detach, err := bpf.AttachProgram(objs, bpf.ProgramSockops)
		if err != nil {
			log.Fatalf("failed to attach program: %v", err)
		}
		defer detach()
	}
	{
		detach, err := bpf.AttachProgram(objs, bpf.ProgramSkSkb)
		if err != nil {
			log.Fatalf("failed to attach program: %v", err)
		}
		defer detach()
	}

	/*
		if err := os.MkdirAll(bpffs, 0755); err != nil {
			log.Fatalf("failed to create fs: %v", err)
		}
		if err := syscall.Mount("none", bpffs, "bpf", 0, ""); err != nil {
			log.Fatalf("failed to mount fs: %v", err)
		}

		if err := objs.Sockmap.Pin(bpffs + "/sockmap"); err != nil {
			log.Fatalf("failed to pin sockmap: %v", err)
		}
		defer objs.Sockmap.Unpin()
	*/

	log.Printf("attached programs")

	<-cmd.Context().Done()
}

/*
func runUpdate(cmd *cobra.Command, args []string) {
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		log.Fatalf("failed to parse pid: %v", err)
	}

	fd, err := strconv.Atoi(args[1])
	if err != nil {
		log.Fatalf("failed to parse fd: %v", err)
	}

	pidFd, err := pidfd.Open(pid, 0)
	if err != nil {
		log.Fatalf("failed to open pidfd: %v", err)
	}

	sockFd, err := pidFd.GetFd(fd, 0)
	if err != nil {
		log.Fatalf("failed to get fd: %v", err)
	}
	log.Println("got sock fd:", sockFd)

	m, err := ebpf.LoadPinnedMap(bpffs+"/sockmap", nil)
	if err != nil {
		log.Fatalf("failed to load pinned map: %v", err)
	}
	defer m.Close()
}
*/
