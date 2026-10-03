package api

import (
	"testing"
	"time"
)

func TestCRLCachePutEvictsExpired(t *testing.T) {
	c := newCRLCache()
	c.entries["old"] = crlCacheEntry{der: []byte{1}, builtAt: time.Now().Add(-2 * crlCacheTTL)}
	c.put("new", []byte{2})
	if _, ok := c.entries["old"]; ok {
		t.Fatal("expired entry was not evicted")
	}
	if _, ok := c.get("new"); !ok {
		t.Fatal("fresh entry missing")
	}
}
