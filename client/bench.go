package client

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

type pgBenchClient struct {
	connString  string
	concurrency int
	rows        int
	duration    time.Duration
	warmup      time.Duration
	queryPerTx  int
	pgc         *pgx.Conn
	wg          sync.WaitGroup
}

type pgBenchResult struct {
	queries int
	msgs    int
}

func NewPgBenchClient(
	ctx context.Context,
	connString string,
	concurrency int,
	rows int,
	duration time.Duration,
	warmup time.Duration,
	queryPerTx int,
	bootstrap bool,
) (*pgBenchClient, error) {
	pgc, err := pgx.Connect(ctx, connString)
	if err != nil {
		return nil, err
	}
	defer pgc.Close(ctx)

	time.Sleep(warmup)

	// Prepare the database
	if bootstrap {
		log.Println("Preparing the database")
		if _, err := pgc.Exec(ctx, "CREATE TABLE IF NOT EXISTS kpgpool_bench (id INT PRIMARY KEY, data INT)"); err != nil {
			return nil, err
		}
		if _, err := pgc.Exec(ctx, "TRUNCATE kpgpool_bench"); err != nil {
			return nil, err
		}
		for i := 0; i < rows; i++ {
			if _, err := pgc.Exec(ctx, "INSERT INTO kpgpool_bench VALUES ($1, $2)", i+1, rand.Intn(65536)); err != nil {
				return nil, err
			}
		}
		log.Println("Prepared the database")
	}

	return &pgBenchClient{
		connString:  connString,
		concurrency: concurrency,
		rows:        rows,
		duration:    duration,
		warmup:      warmup,
		queryPerTx:  queryPerTx,
	}, nil
}

func (c *pgBenchClient) Run(ctx context.Context) {
	pgcs := make([]*pgx.Conn, c.concurrency)
	for i := 0; i < c.concurrency; i++ {
		pgc, err := pgx.Connect(ctx, c.connString)
		if err != nil {
			log.Fatalln("Failed to connect to database:", err)
		}
		pgcs[i] = pgc
	}
	defer func() {
		for i := 0; i < c.concurrency; i++ {
			pgcs[i].Close(ctx)
		}
	}()

	// Warmup connections
	log.Println("Warmup connections")
	time.Sleep(c.warmup)

	log.Printf(
		"Run [concurrency: %d | rows: %d | duration: %s | queryPerTx: %d]",
		c.concurrency, c.rows, c.duration, c.queryPerTx,
	)

	ctx, cancel := context.WithTimeout(ctx, c.duration+c.warmup)
	defer cancel()

	ch := make(chan pgBenchResult, c.concurrency)

	for i := 0; i < c.concurrency; i++ {
		c.wg.Add(1)
		go func(i int) {
			c.run(ctx, pgcs[i], i, ch)
		}(i)
	}

	c.wg.Wait()

	var (
		queries int
		msgs    int
	)
	for i := 0; i < c.concurrency; i++ {
		res := <-ch
		queries += res.queries
		msgs += res.msgs
	}

	log.Printf(
		"Result: [QPS: %f | PPS: %f]",
		float64(queries)/c.duration.Seconds(),
		float64(msgs)/c.duration.Seconds(),
	)
}

func (c *pgBenchClient) run(ctx context.Context, pgc *pgx.Conn, i int, ch chan<- pgBenchResult) {
	defer c.wg.Done()

	var (
		queries int
		msgs    int
		errs    int
		val     int
	)

	defer func() {
		ch <- pgBenchResult{
			queries: queries,
			msgs:    msgs,
		}
		log.Printf("[%d] Messages: %d | Queries: %d | Errors: %d", i, msgs, queries, errs)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if c.queryPerTx == 0 {
				queries++
				msgs++
				if err := pgc.QueryRow(ctx, "SELECT data FROM kpgpool_bench WHERE id = $1", rand.Intn(c.rows)+1).Scan(&val); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return
					}
					errs++
					log.Printf("Failed to query database: %T(%v)", err, err)
				}
				continue
			}

			msgs++
			tx, err := pgc.Begin(ctx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return
				}
				errs++
				log.Printf("Failed to begin transaction %T(%v)", err, err)
				continue
			}
			defer tx.Rollback(ctx)
			for j := 0; j < c.queryPerTx; j++ {
				queries++
				msgs++
				if err := tx.QueryRow(ctx, "SELECT data FROM kpgpool_bench WHERE id = $1", rand.Intn(c.rows)+1).Scan(&val); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return
					}
					errs++
					log.Printf("Failed to query database: %T(%v)", err, err)
				}
			}
			msgs++
			if err := tx.Commit(ctx); err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return
				}
				errs++
				log.Printf("Failed to commit transaction %T(%v)", err, err)
			}
		}
	}
}
