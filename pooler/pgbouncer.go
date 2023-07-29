package pooler

import (
	"context"
	"net"

	"github.com/jackc/pgx/v5"
)

type pgbouncerPooler struct {
	conn *pgx.Conn
}

var _ Pooler = (*pgbouncerPooler)(nil)

func NewPgbouncerPooler(conn *pgx.Conn) *pgbouncerPooler {
	return &pgbouncerPooler{
		conn: conn,
	}
}

func (m *pgbouncerPooler) GetLinks(ctx context.Context) ([]*Link, error) {
	links := make(map[string]*Link)

	{
		rows, err := m.conn.Query(ctx, "show clients")
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				addr string
				port uint16
				link string
			)

			if err := rows.Scan(
				nil, // type
				nil, // user
				nil, // database
				nil, // state
				&addr,
				&port,
				nil, // local_addr
				nil, // local_port
				nil, // connect_time
				nil, // request_time
				nil, // wait
				nil, // wait_us
				nil, // close_needed
				nil, // ptr
				&link,
				nil, // remote_pid
				nil, // tls
				nil, // application_name
			); err != nil {
				return nil, err
			}

			if link == "" {
				continue
			}

			var clientIP uint32 // Network byte order
			if ipv4 := net.ParseIP(addr).To4(); ipv4 != nil {
				clientIP = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
			}

			if clientIP != 0 {
				links[link] = &Link{
					ClientIP:   clientIP,
					ClientPort: port,
				}
			}
		}

		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	{
		rows, err := m.conn.Query(ctx, "show servers")
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				ptr       string
				localPort uint16
			)

			if err := rows.Scan(
				nil, // type
				nil, // user
				nil, // database
				nil, // state
				nil, // addr
				nil, // port
				nil, // local_addr
				&localPort,
				nil, // connect_time
				nil, // request_time
				nil, // wait
				nil, // wait_us
				nil, // close_needed
				&ptr,
				nil, // link
				nil, // remote_pid
				nil, // tls
				nil, // application_name
			); err != nil {
				return nil, err
			}

			if link, ok := links[ptr]; ok {
				link.ServerPort = localPort
			}
		}
	}

	var result []*Link
	for _, link := range links {
		result = append(result, link)
	}

	return result, nil
}
