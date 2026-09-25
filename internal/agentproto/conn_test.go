package agentproto

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPipeRoundTrip(t *testing.T) {
	a, b := Pipe()
	ctx := context.Background()
	if err := a.WriteMsg(ctx, []byte(`{"type":"sync","revision":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err := b.ReadMsg(ctx)
	if err != nil || string(got) != `{"type":"sync","revision":1}` {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestPipeCloseUnblocksRead(t *testing.T) {
	a, b := Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := b.ReadMsg(context.Background())
		done <- err
	}()
	a.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read did not unblock")
	}
	if err := b.WriteMsg(context.Background(), []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after close = %v", err)
	}
}

func TestPipeReadHonoursContext(t *testing.T) {
	_, b := Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.ReadMsg(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}
