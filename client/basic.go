package client

import (
	"context"
	"log"
	"math/rand"
	"sync"

	"github.com/jackc/pgx/v5"
)

type basicClient struct {
	url         string
	concurrency int
}

func NewBasicClient(url string, concurrency int) *basicClient {
	return &basicClient{
		url:         url,
		concurrency: concurrency,
	}
}

func (c *basicClient) Run(ctx context.Context) {
	var wg sync.WaitGroup

	for i := 0; i < c.concurrency; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.run(ctx, i)
		}()
	}

	wg.Wait()
}

func (c *basicClient) run(ctx context.Context, runID int) {
	pgc, err := pgx.Connect(ctx, c.url)
	if err != nil {
		log.Fatalf("[%d] Failed to connect to the database: %v", runID, err)
	}
	defer pgc.Close(ctx)

	var (
		id   int
		data int
	)
	for i := 0; i < 5; i++ {
		if err := pgc.QueryRow(
			ctx,
			"SELECT id, data FROM kpgpool_bench WHERE id = $1",
			rand.Int()%1000+1,
		).Scan(&id, &data); err != nil {
			log.Fatalf("[%d][1-%d] Failed to query: %v", runID, i, err)
		}
		log.Printf("[%d][1-%d] Query result: %d, %d", runID, i, id, data)
	}

	tx, err := pgc.Begin(ctx)
	if err != nil {
		log.Fatalf("[%d] Failed to begin transaction: %v", runID, err)
	}
	for i := 0; i < 5; i++ {
		if err := tx.QueryRow(
			ctx,
			"SELECT id, data FROM kpgpool_bench WHERE id = $1",
			rand.Int()%1000+1,
		).Scan(&id, &data); err != nil {
			log.Fatalf("[%d][2-%d] Failed to query: %v", runID, i, err)
		}
		log.Printf("[%d][2-%d] Query result: %d, %d", runID, i, id, data)
	}
	if err := tx.Commit(ctx); err != nil {
		log.Fatalf("[%d] Failed to commit transaction: %v", runID, err)
	}

	for i := 0; i < 5; i++ {
		if err := pgc.QueryRow(
			ctx,
			"SELECT id, data FROM kpgpool_bench WHERE id = $1",
			rand.Int()%1000+1,
		).Scan(&id, &data); err != nil {
			log.Fatalf("[%d][3-%d] Failed to query: %v", runID, i, err)
		}
		log.Printf("[%d][3-%d] Query result: %d, %d", runID, i, id, data)
	}
}
