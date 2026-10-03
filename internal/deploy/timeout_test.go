package deploy

import (
	"testing"
)

func TestDeployWorkerTimeout(t *testing.T) {
	if got := (&DeployWorker{}).Timeout(nil); got != deployTimeout {
		t.Fatalf("Timeout = %v, want %v", got, deployTimeout)
	}
}
