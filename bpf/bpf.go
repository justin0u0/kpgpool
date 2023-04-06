package bpf

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O3 -Wall -mcpu=v3" bpf ./bpf.c

type Program uint8

const (
	ProgramNone Program = iota
	ProgramPool
)

type DetachFunc func()

func LoadObjects() (*bpfObjects, error) {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}

	return &objs, nil
}

func AttachProgram(objs *bpfObjects, program Program) (DetachFunc, error) {
	switch program {
	case ProgramPool:
		return attachPoolProgram(objs)
	}

	return nil, fmt.Errorf("unknown program: %d", program)
}

func attachSockopsProgram(p *ebpf.Program) (DetachFunc, error) {
	cgroupPath, err := findCgroupPath()
	if err != nil {
		return nil, fmt.Errorf("find cgroup path: %w", err)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: p,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		return nil, fmt.Errorf("attach %s to cgroup %s: %w", p.String(), cgroupPath, err)
	}

	return func() {
		if err := l.Close(); err != nil {
			log.Printf("failed to detach sockops program: %v", err)
		}
	}, nil
}

func attachPoolProgram(objs *bpfObjects) (DetachFunc, error) {
	/*
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.Sockhash.FD(),
		Program: objs.SkSkbStreamParserProgPool,
		Attach:  ebpf.AttachSkSKBStreamParser,
	}); err != nil {
		return nil, err
	}
	*/
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.Sockhash.FD(),
		Program: objs.SkSkbStreamVerdictProgPool,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	}); err != nil {
		return nil, err
	}

	return func() {
		/*
		defer func() {
			if err := link.RawDetachProgram(link.RawDetachProgramOptions{
				Target:  objs.Sockhash.FD(),
				Program: objs.SkSkbStreamParserProgPool,
				Attach:  ebpf.AttachSkSKBStreamParser,
			}); err != nil {
				log.Printf("failed to detach sk_skb stream verdict program: %v", err)
			}
		}()
		*/
		defer func() {
			if err := link.RawDetachProgram(link.RawDetachProgramOptions{
				Target:  objs.Sockhash.FD(),
				Program: objs.SkSkbStreamVerdictProgPool,
				Attach:  ebpf.AttachSkSKBStreamVerdict,
			}); err != nil {
				log.Printf("failed to detach sk_skb stream verdict program: %v", err)
			}
		}()
	}, nil
}

// findCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func findCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
