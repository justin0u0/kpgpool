package main

import (
	"encoding/binary"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

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
	loadCmd.Flags().Bool("load-pairs", false, "load sockmap pairs")

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

	loadPairs, err := cmd.Flags().GetBool("load-pairs")
	if err != nil {
		log.Fatalf("failed to get load-pairs flag: %v", err)
	}

	if loadPairs {
		log.Println("launch load-pairs goroutine")

		go func() {
			for {
				select {
				case <-cmd.Context().Done():
					return
				case <-time.After(5 * time.Second):
					servers := make(map[Socket4Tuple]struct{}, 0)
					clients := make(map[Socket4Tuple]struct{}, 0)

					out, err := exec.Command("/bin/ss", "-et", "( dport = :5432 | sport = :6432 )").Output()
					if err != nil {
						log.Fatalf("failed to run ss: %v", err)
					}

					// parse output
					splits := strings.Split(string(out), "\n")
					// State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port, Process
					for _, line := range splits[1:] {
						fields := strings.Fields(line)

						if len(fields) < 5 {
							continue
						}

						socket := ParseSocket4Tuple(fields[3], fields[4])
						/*
							log.Printf("Parse socket connection %s %s into %X %X %X %X\n", fields[3], fields[4],
								socket.LocalIP4, socket.LocalPort, socket.RemoteIP4, socket.RemotePort)
						*/
						if socket.LocalPort == 6432 {
							clients[socket] = struct{}{}
						} else {
							servers[socket] = struct{}{}
						}
					}

					log.Println("Parse all socket connections:")
					for server := range servers {
						log.Printf("server: %x %x %x %x\n", server.LocalIP4, server.LocalPort, server.RemoteIP4, server.RemotePort)
					}
					for client := range clients {
						log.Printf("client: %x %x %x %x\n", client.LocalIP4, client.LocalPort, client.RemoteIP4, client.RemotePort)
					}
				}
			}
		}()
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

type Socket4Tuple struct {
	LocalIP4   uint32 // network byte order
	LocalPort  uint32 // host byte order
	RemoteIP4  uint32 // network byte order
	RemotePort uint32 // network byte order
}

func ParseSocket4Tuple(local, remote string) Socket4Tuple {
	return Socket4Tuple{
		LocalIP4:   parseIP4(local),
		LocalPort:  parsePort(local, true),
		RemoteIP4:  parseIP4(remote),
		RemotePort: parsePort(remote, false),
	}
}

// parseIP4 parses an IPv4 address in dotted decimal notation into a uint32 in
// network byte order.
func parseIP4(s string) uint32 {
	ipv4 := net.ParseIP(strings.Split(s, ":")[0]).To4()
	if ipv4 == nil {
		return 0
	}
	// go's net.IP is always in big endian
	return binary.LittleEndian.Uint32(ipv4)
}

func parsePort(s string, hostByteOrder bool) uint32 {
	port, err := strconv.Atoi(strings.Split(s, ":")[1])
	if err != nil {
		return 0
	}
	if hostByteOrder {
		return uint32(port)
	}

	return htonl(uint32(port))
}

func htonl(x uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, x)
	return binary.BigEndian.Uint32(b)
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
