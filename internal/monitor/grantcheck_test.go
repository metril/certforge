package monitor_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/monitor"
)

// deploy.GrantCheckArgs is a copy of CheckArgs (import cycle); it must keep
// the same kind, JSON and insert options so River deduplicates the two and
// runs deploy's jobs on the monitor worker.
func TestGrantCheckArgsMatchCheckArgs(t *testing.T) {
	id := uuid.New()
	a, _ := json.Marshal(monitor.CheckArgs{MonitorID: id})
	b, _ := json.Marshal(deploy.GrantCheckArgs{MonitorID: id})
	if string(a) != string(b) {
		t.Errorf("json %s != %s", b, a)
	}
	if (monitor.CheckArgs{}).Kind() != (deploy.GrantCheckArgs{}).Kind() {
		t.Error("kind differs")
	}
	if !reflect.DeepEqual(monitor.CheckArgs{}.InsertOpts(), deploy.GrantCheckArgs{}.InsertOpts()) {
		t.Error("InsertOpts differ")
	}
}
