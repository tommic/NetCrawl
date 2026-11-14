package pgstore

import (
	"context"
	"os"
	"testing"

	"netcrawler/internal/store"
	"netcrawler/internal/store/storetest"
)

// TestConformance runs against the database in NETCRAWL_TEST_DATABASE_URL.
// The database is wiped; never point it at production data.
func TestConformance(t *testing.T) {
	url := os.Getenv("NETCRAWL_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("NETCRAWL_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// Migrations are idempotent.
	if applied, err := s.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Fatalf("second Migrate applied %v, err %v", applied, err)
	}
	storetest.Run(t, func(t *testing.T) store.Store {
		if err := s.Reset(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	})
}
