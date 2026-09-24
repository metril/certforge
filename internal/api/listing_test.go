package api

import (
	"errors"
	"net/http"
	"testing"
)

func problemStatus(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

func TestPaginationAndSort(t *testing.T) {
	keys := map[string]func(a, b string) int{"name": byString(func(s string) string { return s })}
	items := []string{"c", "a", "e", "b", "d"}
	two := 2
	p, err := parseList(nil, nil, nil, &two, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sortItems(items, p, "name", keys); err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		pg, next := page(items, p)
		got = append(got, pg...)
		if next == nil {
			break
		}
		if p, err = parseList(nil, nil, nil, &two, next); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 5 || got[0] != "a" || got[4] != "e" {
		t.Fatalf("pages = %v", got)
	}
	desc := "-name"
	p, _ = parseList(nil, nil, &desc, nil, nil)
	_ = sortItems(items, p, "name", keys)
	if items[0] != "e" {
		t.Fatalf("desc = %v", items)
	}
	bad := "size"
	p, _ = parseList(nil, nil, &bad, nil, nil)
	if s := problemStatus(sortItems(items, p, "name", keys)); s != http.StatusUnprocessableEntity {
		t.Fatalf("unknown sort: %d", s)
	}
	junk := "!!"
	if _, err := parseList(nil, nil, nil, nil, &junk); problemStatus(err) != http.StatusUnprocessableEntity {
		t.Fatalf("bad cursor: %v", err)
	}
	zero := 0
	if _, err := parseList(nil, nil, nil, &zero, nil); problemStatus(err) != http.StatusUnprocessableEntity {
		t.Fatalf("limit 0: %v", err)
	}
}
