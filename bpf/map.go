package bpf

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
)

/*
	struct socket_4_tuple {
		u32 local_ip4;		// network byte order
		u32 local_port;		// host byte order
		u32 remote_ip4;		// network byte order
		u32 remote_port;	// network byte order
	};
*/

type MapDAO struct {
	Objs *bpfObjects
}

func (dao *MapDAO) RegisterServer(conn net.Conn) error {
	val := dao.toBPFSock4Tuple(conn)
	// log.Printf("[RegisterServer] %d %d %d %d", val.LocalIp4, val.LocalPort, val.RemoteIp4, val.RemotePort)
	return dao.Objs.Servers.Put(nil, val)
}

func (dao *MapDAO) SetupServerState(conn net.Conn) error {
	key := dao.toBPFSock4Tuple(conn)
	var state bpfServerState
	return dao.Objs.ServerStates.Put(key, state)
}

func (dao *MapDAO) GetClientState(conn net.Conn) (*bpfClientState, error) {
	key := dao.toBPFSock4Tuple(conn)
	var cs bpfClientState
	if err := dao.Objs.ClientStates.Lookup(key, &cs); err != nil {
		return nil, err
	}
	return &cs, nil
}

func (dao *MapDAO) UpdateServerStatePrepared(conn net.Conn, name []byte) error {
	key := dao.toBPFSock4Tuple(conn)
	var ss bpfServerState
	if err := dao.Objs.ServerStates.Lookup(key, &ss); err != nil {
		return fmt.Errorf("lookup server state: %w", err)
	}

	h := fnv.New32a()
	h.Write(name)
	copy(ss.Prepared[h.Sum32()&0xFF][:], name)

	// log.Println("Update server state prepared statement hash:", h.Sum32())
	if err := dao.Objs.ServerStates.Put(key, ss); err != nil {
		return fmt.Errorf("put server state: %w", err)
	}

	return nil
}

func (dao *MapDAO) SetSockhash(conn net.Conn, fd uint32) error {
	key := dao.toBPFSock4Tuple(conn)
	// log.Printf("[SetSockhash] %d %d %d %d", key.LocalIp4, key.LocalPort, key.RemoteIp4, key.RemotePort)
	return dao.Objs.Sockhash.Put(key, fd)
}

func (dao *MapDAO) SetupClientState(conn net.Conn, id uint32) error {
	key := dao.toBPFSock4Tuple(conn)
	var state bpfClientState
	/*
		copy(state.Id[:], []byte(fmt.Sprintf("%09d", id)))
	*/

	return dao.Objs.ClientStates.Put(key, state)
}

func (dao *MapDAO) toBPFSock4Tuple(conn net.Conn) *bpfSocket4Tuple {
	return &bpfSocket4Tuple{
		LocalIp4:   dao.parseIP4(conn.LocalAddr().(*net.TCPAddr).IP),
		LocalPort:  uint32(conn.LocalAddr().(*net.TCPAddr).Port),
		RemoteIp4:  dao.parseIP4(conn.RemoteAddr().(*net.TCPAddr).IP),
		RemotePort: dao.htonl(uint32(conn.RemoteAddr().(*net.TCPAddr).Port)),
	}
}

func (dao *MapDAO) parseIP4(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

// htonl converts a uint32 from host to network byte order.
func (dao *MapDAO) htonl(x uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, x)
	return binary.BigEndian.Uint32(b)
}

// ntohl converts a uint32 from network to host byte order.
func (dao *MapDAO) ntohl(x uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, x)
	return binary.LittleEndian.Uint32(b)
}
