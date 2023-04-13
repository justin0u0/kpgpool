package bpfgo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/oraoto/go-pidfd"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall" sklookup ./bpf/sklookup.c

var (
	bpffs           = "/usr/fs/bpf"
	sockhashPinPath = bpffs + "/sockhash"
)

func LoadSklookupProg(ctx context.Context, program string) {
	var objs sklookupObjects
	if err := loadSklookupObjects(&objs, nil); err != nil {
		handleLoadError(err)
	}
	defer objs.Close()

	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Fatalf("could not open netns: %s", err)
	}
	defer netns.Close()

	var p *ebpf.Program

	switch program {
	case "debug":
		p = objs.Debug
	case "redirect":
		p = objs.Redirect
	default:
		log.Fatalf("unknown program: %s", program)
	}

	l, err := link.AttachNetNs(int(netns.Fd()), p)
	if err != nil {
		log.Fatalf("could not attach the SK_LOOKUP program: %s", err)
	}
	defer l.Close()

	log.Printf("attached sk_lookup/%s program to netns: %d", program, netns.Fd())

	if err := mountBpffs(); err != nil {
		log.Fatalf("could not mount bpffs: %s", err)
	}

	if err := objs.Sockhash.Pin(sockhashPinPath); err != nil {
		log.Fatalf("could not pin sockhash map: %s", err)
	}
	defer func() {
		// FIXME: unpin is not working now
		if err := objs.Sockhash.Unpin(); err != nil {
			log.Printf("could not unpin sockhash map: %s", err)
		}
	}()
	log.Printf("pinned sockhash map to %s", sockhashPinPath)

	info, err := objs.Sockhash.Info()
	if err != nil {
		log.Fatalf("could not get sockhash map info: %s", err)
	}
	if id, ok := info.ID(); ok {
		log.Println("sockhash map id:", id, "fd:", objs.Sockhash.FD())
	}

	<-ctx.Done()

	log.Printf("detaching sk_lookup/%s program", program)
}

// UpdateSockhashMap updates the socket FD into the sockhash map with the given key.
func UpdateSockhashMap(pid, fd int, key uint64) {
	m, err := ebpf.LoadPinnedMap(sockhashPinPath, nil)
	if err != nil {
		log.Fatalf("could not load pinned sockhash map: %s", err)
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		log.Fatalf("could not get sockhash map info: %s", err)
	}
	if id, ok := info.ID(); ok {
		log.Println("sockhash map id:", id, "fd:", m.FD())
	}

	pidFd, err := pidfd.Open(pid, 0)
	if err != nil {
		log.Fatalf("could not open pidfd: %s", err)
	}

	sockFd, err := pidFd.GetFd(fd, 0)
	if err != nil {
		log.Fatalf("could not get socket fd: %s", err)
	}

	log.Println("current pid:", os.Getpid(), "get pid:", pid, "fd:", fd, "sockfd:", sockFd)

	var value uint32 = uint32(sockFd)
	if err := m.Put(&key, &value); err != nil {
		log.Fatalf("could not update sockhash map: %s", err)
	}

	log.Println("updated sockhash map with key:", key, "value:", value)
}

func handleLoadError(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		for _, l := range ve.Log {
			fmt.Println(l)
		}
	}
	log.Fatalf("could not load program: %s", err)
}

func mountBpffs() error {
	if err := os.MkdirAll(bpffs, 0755); err != nil {
		return fmt.Errorf("could not create bpffs directory: %s", err)
	}

	if err := syscall.Mount("bpf", bpffs, "bpf", 0, ""); err != nil {
		return fmt.Errorf("could not mount bpffs: %s", err)
	}

	return nil
}
