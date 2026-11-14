package memstore

import (
	"testing"

	"netcrawler/internal/store"
	"netcrawler/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return New() })
}
