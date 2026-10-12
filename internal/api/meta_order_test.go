package api

import (
	"reflect"
	"testing"
)

func TestPropertyOrderKeepsSourceOrder(t *testing.T) {
	raw := []byte(`{"type":"object","properties":{"url":{"type":"string"},"username":{"properties":{"z":{}}},"password":{},"caPem":{}}}`)
	want := []string{"url", "username", "password", "caPem"}
	if got := propertyOrder(raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := propertyOrder([]byte(`{"type":"object"}`)); got != nil {
		t.Fatalf("no properties: got %v", got)
	}
}
