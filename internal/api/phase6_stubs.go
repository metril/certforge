package api

import (
	"context"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
)

// Phase 6A contract stubs. These operations are declared in api/openapi.yaml
// (Task 2) but not yet implemented; Task 12 (CreateBackup/GetBackupStatus)
// moves its own method out of this file into its resource file and, once
// the last one leaves (Task 14), this file is deleted. Channel and event
// operations moved out in Task 6 (internal/api/channels.go,
// internal/api/events.go). TestSmtpSettings moved out in Task 5
// (internal/api/settings.go). Monitor operations moved out in Task 9
// (internal/api/monitors.go). getServerInfo is real from Task 2 on
// (internal/api/server_info.go), not a stub here.

var errPhase6NotImplemented = &HTTPError{Status: http.StatusNotImplemented, Title: "Not implemented"}

// CreateBackup is implemented in Task 12 (backup API, schedule, readiness).
func (s *Server) CreateBackup(context.Context, gen.CreateBackupRequestObject) (gen.CreateBackupResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// GetBackupStatus is implemented in Task 12 (backup API, schedule, readiness).
func (s *Server) GetBackupStatus(context.Context, gen.GetBackupStatusRequestObject) (gen.GetBackupStatusResponseObject, error) {
	return nil, errPhase6NotImplemented
}
