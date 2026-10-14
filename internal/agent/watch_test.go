package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func shortDebounce(t *testing.T) {
	t.Helper()
	old := watchDebounce
	watchDebounce = 60 * time.Millisecond
	t.Cleanup(func() { watchDebounce = old })
}

func startWatcher(t *testing.T, paths ...string) (*fileWatcher, chan struct{}) {
	return startSuppressed(t, nil, paths...)
}

func startSuppressed(t *testing.T, quiet func() bool, paths ...string) (*fileWatcher, chan struct{}) {
	t.Helper()
	shortDebounce(t)
	fw, err := newFileWatcher(discard)
	if err != nil {
		t.Skipf("no file watcher here: %v", err)
	}
	fw.suppressed = quiet
	fw.Sync(paths)
	ctx, cancel := context.WithCancel(context.Background())
	changed := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { defer close(done); fw.Run(ctx, changed) }()
	t.Cleanup(func() { cancel(); fw.Close(); <-done })
	return fw, changed
}

func expectSignal(t *testing.T, ch chan struct{}, want bool) {
	t.Helper()
	select {
	case <-ch:
		if !want {
			t.Fatal("unexpected signal")
		}
	case <-time.After(1500 * time.Millisecond):
		if want {
			t.Fatal("no signal")
		}
	}
}

func TestWatcherSignalsEachChangeKind(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.pem")
	_ = os.WriteFile(p, []byte("one"), 0o644)
	_, ch := startWatcher(t, p)

	if err := os.WriteFile(p, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectSignal(t, ch, true)

	tmp := filepath.Join(dir, "a.pem.tmp")
	_ = os.WriteFile(tmp, []byte("three"), 0o644)
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
	expectSignal(t, ch, true)

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	expectSignal(t, ch, true)
	if err := os.WriteFile(p, []byte("four"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectSignal(t, ch, true)
}

func TestWatcherIgnoresUnrelatedFilesAndCoalescesBursts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.pem")
	_ = os.WriteFile(p, []byte("x"), 0o644)
	_, ch := startWatcher(t, p)

	_ = os.WriteFile(filepath.Join(dir, "other.txt"), []byte("y"), 0o644)
	expectSignal(t, ch, false)

	for i := range 10 {
		_ = os.WriteFile(p, []byte{byte(i)}, 0o644)
	}
	expectSignal(t, ch, true)
	expectSignal(t, ch, false)
}

func TestWatcherSyncDropsDirs(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	p1, p2 := filepath.Join(d1, "a"), filepath.Join(d2, "b")
	fw, _ := startWatcher(t, p1, p2)
	if len(fw.dirs) != 2 {
		t.Fatalf("dirs %v", fw.dirs)
	}
	fw.Sync([]string{p1})
	if len(fw.dirs) != 1 || !fw.dirs[d1] || fw.watching(p2) {
		t.Fatalf("dirs %v", fw.dirs)
	}
	fw.Sync(nil)
	if len(fw.dirs) != 0 {
		t.Fatalf("dirs %v", fw.dirs)
	}
}

func TestWatcherSyncReportsUnwatchableDir(t *testing.T) {
	fw, _ := startWatcher(t, filepath.Join(t.TempDir(), "missing", "a.pem"))
	if fw.Reason() == "" {
		t.Fatal("no reason for an unwatchable directory")
	}
}

func TestWatcherConstructorFailure(t *testing.T) {
	old := newWatcher
	newWatcher = func() (*fsnotify.Watcher, error) { return nil, errors.New("inotify limit") }
	defer func() { newWatcher = old }()
	if fw, err := newFileWatcher(discard); err == nil || fw != nil {
		t.Fatalf("fw %v err %v", fw, err)
	}
	a := &Agent{Log: discard, ID: &Identity{}}
	wc := newWatchCtl(context.Background(), a)
	wc.Set(true)
	if st := wc.Status(); st.Active || st.Reason != "inotify limit" {
		t.Fatalf("status %+v", st)
	}
}

func TestWatcherSuppressedWhileReconciling(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.pem")
	_ = os.WriteFile(p, []byte("x"), 0o644)
	wc := newWatchCtl(context.Background(), &Agent{})
	_, ch := startSuppressed(t, wc.quiet, p)
	wc.Begin()
	_ = os.WriteFile(p, []byte("y"), 0o644)
	wc.End()
	expectSignal(t, ch, false) // the write landed during the reconcile
	time.Sleep(watchDebounce + 20*time.Millisecond)
	_ = os.WriteFile(p, []byte("z"), 0o644)
	expectSignal(t, ch, true)
}

func TestWatchCtlStatus(t *testing.T) {
	id := &Identity{}
	a := &Agent{Log: discard, ID: id}
	wc := newWatchCtl(context.Background(), a)
	defer wc.Close()
	wc.Set(false)
	if st := wc.Status(); st.Active || st.Reason != "disabled" {
		t.Fatalf("server off %+v", st)
	}
	wc.Set(true)
	if st := wc.Status(); !st.Active {
		t.Skipf("no watcher here: %+v", st)
	}
	wc.Set(false)
	if wc.fw != nil {
		t.Fatal("watcher kept after the server turned it off")
	}
	a.Cfg.NoWatchFiles = true
	wc.Set(true)
	if st := wc.Status(); st.Active || wc.fw != nil || st.Reason == "" {
		t.Fatalf("local override %+v", st)
	}
}

func TestWatcherSyncReaddsRecreatedDir(t *testing.T) {
	base := t.TempDir()
	d := filepath.Join(base, "out")
	_ = os.Mkdir(d, 0o755)
	p := filepath.Join(d, "a.pem")
	fw, ch := startWatcher(t, p)
	_ = os.RemoveAll(d)
	_ = os.Mkdir(d, 0o755)
	fw.Sync([]string{p})
	if fw.Reason() != "" {
		t.Fatalf("reason %q", fw.Reason())
	}
	time.Sleep(100 * time.Millisecond)
	for len(ch) > 0 {
		<-ch
	}
	_ = os.WriteFile(p, []byte("x"), 0o644)
	expectSignal(t, ch, true)
}
