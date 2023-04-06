package pooler

import "context"

type Link struct {
	ClientIP   uint32 // Network byte order
	ClientPort uint16 // Host byte order
	ServerPort uint16 // Network byte order
}

type Pooler interface {
	GetLinks(ctx context.Context) ([]*Link, error)
}
