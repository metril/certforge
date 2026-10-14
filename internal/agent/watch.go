package agent

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/metril/certforge/internal/agentproto"
)

// watchDebounce is how long events must stay quiet before one signal is sent,
// and how long after a reconcile the agent's own writes are ignored. A var so
// tests can shorten it.
var watchDebounce = 2 * time.Second

// newWatcher is a seam so tests can fail the constructor.
var newWatcher = func() (*fsnotify.Watcher, error) { return fsnotify.NewWatcher() }

// fileWatcher watches the parent directories of the installed files (so an
// atomic rename-over or a delete and recreate is still seen) and signals when
// one of the files changes.
type fileWatcher struct {
	w   *fsnotify.Watcher
	log *slog.Logger

	// onChange is called with each changed installed path, before debouncing
	// and suppression, so a digest cache can be invalidated.
	onChange func(path string)
	// suppressed drops the signal (not onChange) while the agent writes.
	suppressed func() bool

	mu     sync.Mutex
	paths  map[string]bool
	dirs   map[string]bool
	reason string // why the last Sync could not watch everything
}

// newFileWatcher returns nil when the OS watcher cannot start (for example
// the inotify limit); the caller then falls back to the heartbeat ticker.
func newFileWatcher(log *slog.Logger) (*fileWatcher, error) {
	w, err := newWatcher()
	if err != nil {
		return nil, err
	}
	return &fileWatcher{w: w, log: log, paths: map[string]bool{}, dirs: map[string]bool{}}, nil
}

// Sync makes paths the watched set, adding and dropping parent directories as
// needed. A directory that cannot be watched is reported through Reason.
func (f *fileWatcher) Sync(paths []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = map[string]bool{}
	want := map[string]bool{}
	for _, p := range paths {
		p = filepath.Clean(p)
		f.paths[p] = true
		want[filepath.Dir(p)] = true
	}
	for d := range f.dirs {
		if !want[d] {
			_ = f.w.Remove(d)
			delete(f.dirs, d)
		}
	}
	f.reason = ""
	for d := range want {
		// Add every time (it is idempotent): inotify drops the watch of a
		// deleted directory, so a recreated one must be added again.
		if err := f.w.Add(d); err != nil {
			delete(f.dirs, d)
			if f.reason == "" {
				f.reason = fmt.Sprintf("cannot watch %s: %v", d, err)
			}
			continue
		}
		f.dirs[d] = true
	}
}

// Reason is why the last Sync could not watch every directory, or "".
func (f *fileWatcher) Reason() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reason
}

func (f *fileWatcher) watching(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.paths[filepath.Clean(name)]
}

// Run sends one value on changed (never blocking) after events on installed
// paths settle for watchDebounce. It returns when ctx ends or the watcher is
// closed.
func (f *fileWatcher) Run(ctx context.Context, changed chan<- struct{}) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	fire := func() {
		if f.suppressed != nil && f.suppressed() {
			return
		}
		timer.Reset(watchDebounce)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-f.w.Events:
			if !ok {
				return
			}
			if !f.watching(ev.Name) {
				continue
			}
			if f.onChange != nil {
				f.onChange(filepath.Clean(ev.Name))
			}
			fire()
		case err, ok := <-f.w.Errors:
			if !ok {
				return
			}
			f.log.Warn("file watcher error; checking files now", "err", err)
			fire()
		case <-timer.C:
			// Events during the debounce were suppressed at arrival; one
			// that began before a reconcile but fires inside it is dropped.
			if f.suppressed != nil && f.suppressed() {
				continue
			}
			select {
			case changed <- struct{}{}:
			default:
			}
		}
	}
}

// Close stops the watcher.
func (f *fileWatcher) Close() { _ = f.w.Close() }

// watchCtl owns a session's watcher: it starts and stops it as the server
// setting changes, re-syncs it after reconciles and reports its health.
type watchCtl struct {
	a       *Agent
	ctx     context.Context
	changed chan struct{} // buffered 1: a watched file changed

	busy  atomic.Bool  // a reconcile is writing files
	until atomic.Int64 // unix nanos: ignore events until then

	mu       sync.Mutex
	fw       *fileWatcher
	cancel   context.CancelFunc
	done     chan struct{}
	serverOn bool
	startErr string
}

func newWatchCtl(ctx context.Context, a *Agent) *watchCtl {
	return &watchCtl{a: a, ctx: ctx, changed: make(chan struct{}, 1), serverOn: true}
}

func (c *watchCtl) quiet() bool {
	return c.busy.Load() || time.Now().UnixNano() < c.until.Load()
}

// Begin and End bracket a reconcile so its own writes do not signal.
func (c *watchCtl) Begin() { c.busy.Store(true) }
func (c *watchCtl) End() {
	c.until.Store(time.Now().Add(watchDebounce).UnixNano())
	c.busy.Store(false)
}

// Set applies the server's setting: true starts the watcher (unless the agent
// config forbids it), false stops it.
func (c *watchCtl) Set(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serverOn = on
	if !on || c.a.Cfg.NoWatchFiles {
		c.stopLocked()
		return
	}
	if c.fw != nil {
		return
	}
	fw, err := newFileWatcher(c.a.Log)
	if err != nil {
		c.startErr = err.Error()
		c.a.Log.Warn("file watcher unavailable; relying on the heartbeat", "err", err)
		return
	}
	c.startErr = ""
	fw.suppressed = c.quiet
	fw.onChange = c.a.ID.invalidate
	fw.Sync(c.a.ID.InstalledPaths())
	rctx, cancel := context.WithCancel(c.ctx)
	c.fw, c.cancel, c.done = fw, cancel, make(chan struct{})
	go func() { defer close(c.done); fw.Run(rctx, c.changed) }()
}

// Sync re-reads the installed paths, after a reconcile changed them.
func (c *watchCtl) Sync() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fw != nil {
		c.fw.Sync(c.a.ID.InstalledPaths())
	}
}

func (c *watchCtl) stopLocked() {
	if c.fw == nil {
		return
	}
	c.cancel()
	c.fw.Close()
	<-c.done
	c.fw, c.cancel, c.done = nil, nil, nil
}

// Close stops the watcher.
func (c *watchCtl) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

// Status is the watcher health for the heartbeat.
func (c *watchCtl) Status() *agentproto.FileWatchStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.a.Cfg.NoWatchFiles:
		return &agentproto.FileWatchStatus{Reason: "disabled in the agent config"}
	case !c.serverOn:
		return &agentproto.FileWatchStatus{Reason: "disabled"}
	case c.fw == nil:
		return &agentproto.FileWatchStatus{Reason: c.startErr}
	}
	r := c.fw.Reason()
	return &agentproto.FileWatchStatus{Active: r == "", Reason: r}
}
