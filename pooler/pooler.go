package pooler

import "context"

type Link struct {
	// ClientIP is the IP address of the PostgreSQL client. Network byte order.
	ClientIP uint32
	// ClientPort is the port number of the PostgreSQL client. Host byte order.
	ClientPort uint16
	// ServerPort is the pooler port number that connects to the PostgreSQL server. Host byte order.
	ServerPort uint16
}

func (l *Link) Key() uint64 {
	return uint64(l.ClientIP)<<32 | uint64(l.ClientPort)
}

type Pooler interface {
	GetLinks(ctx context.Context) ([]*Link, error)
}
